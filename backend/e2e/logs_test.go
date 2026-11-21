package e2e

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Everything Guardian logs during the end-to-end tests is kept, and checked once they have run: the log
// must hold no email address and no IP address (account ids are the most a log may hold). The tests sign in,
// sign up, send email and fail in every way, so this covers what the server logs in practice.

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

var serverLog logBuffer

func captureLogs() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, &serverLog), nil)))
}

var (
	emailInLog = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	// IPv4, and IPv6 with at least six groups or "::" (so clock times such as 03:47:15 do not count).
	ipInLog = regexp.MustCompile(`(?i)\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b(?:[0-9a-f]{1,4}:){5,7}[0-9a-f]{1,4}\b|[0-9a-f]{0,4}::[0-9a-f]{1,4}\b`)
)

// personalDataInLogs returns the logged lines that hold an email or IP address. The database's own
// address in the startup line is configuration, not a person.
func personalDataInLogs() []string {
	serverLog.mu.Lock()
	defer serverLog.mu.Unlock()
	var found []string
	for _, line := range strings.Split(serverLog.buf.String(), "\n") {
		if strings.Contains(line, `msg="connected to the database"`) {
			continue
		}
		if emailInLog.MatchString(line) || ipInLog.MatchString(line) {
			found = append(found, line)
		}
	}
	return found
}

func checkLogs() int {
	found := personalDataInLogs()
	if len(found) == 0 {
		return 0
	}
	fmt.Fprintln(os.Stderr, "FAIL: the server logged personal data (email or IP addresses):")
	for _, l := range found {
		fmt.Fprintln(os.Stderr, "  ", l)
	}
	return 1
}
