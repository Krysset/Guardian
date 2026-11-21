package mail

import (
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func TestEveryEmailRendersBothPartsAndEscapes(t *testing.T) {
	Configure(nil, Site{Name: `Hyrule <Guardian>`, Host: "auth.test"})
	t.Cleanup(func() { Configure(nil, Site{}) })
	when := time.Date(2026, 11, 15, 13, 2, 0, 0, time.UTC)
	link := "https://auth.test/confirm?token=abc&x=<y>"
	for name, m := range map[string]Message{
		"confirm":     ConfirmAddress("a@b.test", link, when, "Europe/Stockholm", false),
		"signup":      ConfirmAddress("a@b.test", link, when, "", true),
		"reset":       ResetPassword("a@b.test", link, when, "Europe/Stockholm"),
		"changed":     PasswordChanged("a@b.test", when, "Nowhere/Invalid"),
		"changing":    EmailChanging("a@b.test", "zelda@castle.example", when, ""),
		"mfa added":   TwoFactorChanged("a@b.test", true, "Authenticator app", when, ""),
		"mfa removed": TwoFactorChanged("a@b.test", false, "Authenticator app", when, ""),
		"mfa reset":   TwoFactorReset("a@b.test", "Lost <phone>", when, ""),
		"has account": AddressHasAccount("a@b.test", link, link),
	} {
		if m.To != "a@b.test" || m.Subject == "" {
			t.Errorf("%s: to %q, subject %q", name, m.To, m.Subject)
		}
		if strings.Contains(m.HTML, "<Guardian>") || strings.Contains(m.HTML, "<y>") {
			t.Errorf("%s: the HTML part is not escaped", name)
		}
		if !strings.Contains(m.HTML, "Hyrule &lt;Guardian&gt;") || !strings.Contains(m.Text, "Hyrule <Guardian>") {
			t.Errorf("%s: the site name is missing", name)
		}
		if !strings.Contains(m.Text, "Wasn't you?") || !strings.Contains(m.Text, "You can't turn off security emails.") {
			t.Errorf("%s: the text part lacks its notes:\n%s", name, m.Text)
		}
		if name == "confirm" || name == "signup" || name == "reset" {
			if !strings.Contains(m.Text, link) || !strings.Contains(m.HTML, `href="https://auth.test/confirm?token=abc&amp;x=%3cy%3e"`) {
				t.Errorf("%s: the link is missing:\n%s", name, m.HTML)
			}
		}
	}
	// The group request emails and the daily summary are not about security, and say why they came instead.
	for name, m := range map[string]Message{
		"summary":   DailySummary("a@b.test", []Item{{"Zelda <z> asks to join Knights", "21 Nov", link}}, link),
		"requested": GroupRequested("a@b.test", "Zelda <z>", "Knights", "Let me <in>", link, link, when, ""),
		"approved":  GroupRequestDecided("a@b.test", "Knights", true, link, when, ""),
		"denied":    GroupRequestDecided("a@b.test", "Knights", false, link, when, ""),
	} {
		if strings.Contains(m.Text, "security emails") || !strings.Contains(m.Text, "You get this because") {
			t.Errorf("%s: footer:\n%s", name, m.Text)
		}
		if strings.Contains(m.HTML, "<in>") || strings.Contains(m.HTML, "Zelda <z>") {
			t.Errorf("%s: not escaped", name)
		}
	}
	if m := ConfirmAddress("a@b.test", link, when, "Europe/Stockholm", false); !strings.Contains(m.Text, "15 Nov 2026 at 14:02 (Europe/Stockholm)") {
		t.Errorf("times are shown in the account's zone: %s", m.Text)
	}
	if m := PasswordChanged("a@b.test", when, "Nowhere/Invalid"); !strings.Contains(m.Text, "15 Nov 2026 at 13:02 (UTC)") {
		t.Errorf("an unknown zone falls back to UTC: %s", m.Text)
	}
	if m := EmailChanging("a@b.test", "zelda@castle.example", when, ""); strings.Contains(m.Text, "zelda@") || !strings.Contains(m.Text, "z•••@castle.example") {
		t.Error("the notice to the old address must mask the new one")
	}
}

func TestMask(t *testing.T) {
	for in, want := range map[string]string{"alice@example.com": "a•••@example.com", "ö@x.se": "ö•••@x.se", "nonsense": "•••", "@x": "•••"} {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestComposeIsAValidMultipartMessage(t *testing.T) {
	from := mail.Address{Name: "Hyrule Guardian", Address: "no-reply@auth.test"}
	raw := Compose(from, Message{To: "a@b.test", Subject: "Ändrat lösenord", Text: "Hej\nlong " + strings.Repeat("x", 200), HTML: "<p>Hej</p>"}, time.Now())
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject")); subject != "Ändrat lösenord" {
		t.Errorf("subject = %q", subject)
	}
	if msg.Header.Get("Auto-Submitted") != "auto-generated" || msg.Header.Get("Message-ID") == "" || !strings.HasSuffix(msg.Header.Get("Message-ID"), "@auth.test>") {
		t.Errorf("headers = %v", msg.Header)
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	r := multipart.NewReader(msg.Body, params["boundary"])
	var types []string
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(p) // the multipart reader decodes quoted-printable
		types = append(types, p.Header.Get("Content-Type"))
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/plain") && !strings.Contains(string(body), strings.Repeat("x", 200)) {
			t.Errorf("the long line did not survive quoted-printable: %q", body)
		}
	}
	if strings.Join(types, ",") != "text/plain; charset=utf-8,text/html; charset=utf-8" {
		t.Errorf("parts = %q", types)
	}
	for _, line := range strings.Split(string(raw), "\r\n") {
		if len(line) > 998 {
			t.Fatal("a line is longer than SMTP allows")
		}
	}
}

// fakeSMTP accepts one message and hands its envelope and data to the test.
func fakeSMTP(t *testing.T) (port int, got <-chan [3]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan [3]string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tp := textproto.NewConn(conn)
		tp.PrintfLine("220 fake ESMTP")
		var from, to string
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return
			}
			switch cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0]); cmd {
			case "EHLO", "HELO":
				tp.PrintfLine("250-fake\r\n250 8BITMIME")
			case "MAIL":
				from = line
				tp.PrintfLine("250 ok")
			case "RCPT":
				to = line
				tp.PrintfLine("250 ok")
			case "DATA":
				tp.PrintfLine("354 go")
				data, _ := io.ReadAll(tp.DotReader())
				ch <- [3]string{from, to, string(data)}
				tp.PrintfLine("250 queued")
			case "QUIT":
				tp.PrintfLine("221 bye")
				return
			default:
				tp.PrintfLine("502 no")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ch
}

func TestSMTPSendsAndStartTLSIsRequired(t *testing.T) {
	port, got := fakeSMTP(t)
	s := SMTP{Host: "127.0.0.1", Port: port, Security: "none", From: mail.Address{Name: "G", Address: "no-reply@auth.test"}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Send(ctx, Message{To: "a@b.test", Subject: "Hi", Text: "t", HTML: "<p>h</p>"}); err != nil {
		t.Fatal(err)
	}
	e := <-got
	if !strings.HasPrefix(e[0], "MAIL FROM:<no-reply@auth.test>") {
		t.Errorf("envelope sender = %q", e[0])
	}
	if !strings.HasPrefix(e[1], "RCPT TO:<a@b.test>") || !strings.Contains(e[2], "Subject: Hi") {
		t.Errorf("rcpt %q, data %.200q", e[1], e[2])
	}

	// The fake server offers no STARTTLS: with starttls the password must never go out in the clear.
	port, _ = fakeSMTP(t)
	s.Port, s.Security = port, "starttls"
	if err := s.Send(ctx, Message{To: "a@b.test"}); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("starttls against a server without it: %v", err)
	}
}

func TestQueueDeliversInTheBackground(t *testing.T) {
	c := &Capture{}
	Configure(c, Site{})
	t.Cleanup(func() { Configure(nil, Site{}) })
	if !Enabled() {
		t.Fatal("not enabled with a sender")
	}
	Enqueue(Message{To: "a@b.test", Subject: "One"})
	if _, ok := c.WaitFor("a@b.test", "One"); !ok {
		t.Fatal("the queued message was not sent")
	}
	Configure(nil, Site{})
	Enqueue(Message{To: "a@b.test", Subject: "Two"})
	time.Sleep(50 * time.Millisecond)
	if len(c.Messages()) != 1 || Enabled() {
		t.Error("email still goes out after it was turned off")
	}
}

// A mail server's refusal often quotes the address; the log gets the answer without it.
func TestFailuresAreLoggedWithoutTheAddress(t *testing.T) {
	for _, c := range []struct{ err, to, want string }{
		{"550 5.1.1 <zelda@hyrule.example>: Recipient address rejected", "zelda@hyrule.example", "550 5.1.1 <(address)>: Recipient address rejected"},
		{"452 too many recipients, last was link@hyrule.example", "zelda@hyrule.example", "452 too many recipients, last was (address)"},
		{"dial tcp: connection refused", "zelda@hyrule.example", "dial tcp: connection refused"},
	} {
		if got := redact(errorString(c.err), c.to); got != c.want {
			t.Errorf("redact(%q) = %q, want %q", c.err, got, c.want)
		}
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }
