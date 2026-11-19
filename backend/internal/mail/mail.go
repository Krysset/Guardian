// Package mail sends Guardian's emails: confirmation links, password reset links and security notices.
//
// Emails are queued and sent in the background, so a page answers at once and its timing does not reveal
// whether an email went out (the password-reset page must not tell whether an account exists). The queue
// lives in memory: an email queued just before a replica stops is lost, and the user asks for a new link.
// That is acceptable for links and notices; nothing else depends on an email arriving.
package mail

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Message is one email to one recipient.
type Message struct {
	To      string
	Subject string
	Text    string // the plain-text part
	HTML    string // the HTML part
}

// Sender delivers a message, or fails.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

var sent = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "guardian", Name: "mail_sent_total", Help: "Emails by result: sent, failed (after retries) or dropped (queue full).",
}, []string{"result"})

const queueSize = 256

// retryDelays are the waits between attempts. A failed email is given up after the last one.
var retryDelays = []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute}

var (
	mu     sync.RWMutex
	sender Sender
	queue  chan Message
	site   = Site{Name: "Guardian"}
)

// Site is what the emails say about who sends them.
type Site struct {
	Name string // shown in the email header and the footer, e.g. "Hyrule Guardian"
	Host string // the issuer's host, e.g. auth.example.com
}

// Configure sets the sender and starts the background queue. A nil sender turns email off: Enabled reports
// false and Enqueue drops messages.
func Configure(s Sender, info Site) {
	mu.Lock()
	defer mu.Unlock()
	sender, site = s, info
	if site.Name == "" {
		site.Name = "Guardian"
	}
	if s != nil && queue == nil {
		queue = make(chan Message, queueSize)
		go work(queue)
	}
}

// Enabled reports whether Guardian can send email. Without it, sign-up has no email field and passwords
// can only be reset by an administrator.
func Enabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return sender != nil
}

func currentSite() Site {
	mu.RLock()
	defer mu.RUnlock()
	return site
}

// Enqueue queues a message for sending and returns at once.
func Enqueue(m Message) {
	mu.RLock()
	q, on := queue, sender != nil
	mu.RUnlock()
	if !on {
		return
	}
	select {
	case q <- m:
	default:
		sent.WithLabelValues("dropped").Inc()
		slog.Error("email queue is full; an email was dropped", "subject", m.Subject)
	}
}

func work(q chan Message) {
	for m := range q {
		deliver(m)
	}
}

func deliver(m Message) {
	for attempt := 0; ; attempt++ {
		mu.RLock()
		s := sender
		mu.RUnlock()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := s.Send(ctx, m)
		cancel()
		if err == nil {
			sent.WithLabelValues("sent").Inc()
			return
		}
		if attempt == len(retryDelays) {
			sent.WithLabelValues("failed").Inc()
			// The recipient's address is personal data and stays out of the log.
			slog.Error("an email could not be sent", "subject", m.Subject, "error", err)
			return
		}
		slog.Warn("sending an email failed; trying again", "subject", m.Subject, "error", err, "attempt", attempt+1)
		time.Sleep(retryDelays[attempt])
	}
}

// Capture is a Sender for tests: it keeps every message.
type Capture struct {
	mu   sync.Mutex
	msgs []Message
}

func (c *Capture) Send(_ context.Context, m Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
	return nil
}

// Messages returns the messages sent so far.
func (c *Capture) Messages() []Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Message(nil), c.msgs...)
}

// Reset forgets the messages sent so far.
func (c *Capture) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = nil
}

// WaitFor waits up to two seconds for a message to the address whose subject contains subject, and
// returns the newest such message.
func (c *Capture) WaitFor(to, subject string) (Message, bool) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		msgs := c.Messages()
		for i := len(msgs) - 1; i >= 0; i-- {
			if msgs[i].To == to && strings.Contains(msgs[i].Subject, subject) {
				return msgs[i], true
			}
		}
		if time.Now().After(deadline) {
			return Message{}, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}
