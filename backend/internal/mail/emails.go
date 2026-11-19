package mail

import (
	"bytes"
	"embed"
	htmltemplate "html/template"
	"strings"
	texttemplate "text/template"
	"time"
	"unicode/utf8"
)

// The emails are designed on the design board (E1-E6). Every email has the same parts, so one HTML and one
// text template render them all from an email value.

//go:embed templates/*
var templateFiles embed.FS

var (
	htmlTemplate = htmltemplate.Must(htmltemplate.ParseFS(templateFiles, "templates/email.html"))
	textTemplate = texttemplate.Must(texttemplate.ParseFS(templateFiles, "templates/email.txt"))
)

type email struct {
	Site    Site
	Subject string
	Lines   []string // paragraphs
	Button  *button
	Small   string // under the button: how long the link works
	Facts   []fact
	NotMe   string // "Wasn't you?" and what to do then
}

type button struct{ Label, URL string }
type fact struct{ Label, Value string }

func (e email) message(to string) Message {
	e.Site = currentSite()
	var h, t bytes.Buffer
	if err := htmlTemplate.Execute(&h, e); err != nil {
		panic(err) // the templates are fixed; a failure is a bug caught by the tests
	}
	if err := textTemplate.Execute(&t, e); err != nil {
		panic(err)
	}
	return Message{To: to, Subject: e.Subject, HTML: h.String(), Text: t.String()}
}

// When formats a time for an email, in the account's time zone when it has one: "15 Nov 2026 at 14:02
// (Europe/Stockholm)".
func When(t time.Time, zone string) string {
	loc, err := time.LoadLocation(zone)
	if zone == "" || err != nil {
		loc, zone = time.UTC, "UTC"
	}
	return t.In(loc).Format("2 Jan 2006 at 15:04") + " (" + zone + ")"
}

// Mask hides most of an address: alice@example.com becomes a•••@example.com.
func Mask(address string) string {
	at := strings.LastIndex(address, "@")
	if at <= 0 {
		return "•••"
	}
	r, _ := utf8.DecodeRuneInString(address)
	return string(r) + "•••" + address[at:]
}

// ConfirmAddress is E1: the link that confirms an email address, at sign-up or when the address changes.
func ConfirmAddress(to, link string, expires time.Time, zone string, signup bool) Message {
	lines := []string{"Someone, hopefully you, added this address to a Guardian account. Confirm it so you can reset your password by email."}
	notMe := "Ignore this email. The address won't be added."
	if signup {
		lines = []string{"Someone, hopefully you, created a Guardian account with this address. Confirm it to finish creating the account."}
		notMe = "Ignore this email. The account won't be created."
	}
	return email{
		Subject: "Confirm your email address",
		Lines:   lines,
		Button:  &button{"Confirm this address", link},
		Small:   "The link works once, until " + When(expires, zone) + ".",
		NotMe:   notMe,
	}.message(to)
}

// ResetPassword is E2: the link to choose a new password.
func ResetPassword(to, link string, expires time.Time, zone string) Message {
	return email{
		Subject: "Reset your password",
		Lines:   []string{"Someone asked to reset the password of your Guardian account."},
		Button:  &button{"Choose a new password", link},
		Small:   "The link works once, until " + When(expires, zone) + ". Two-factor still applies when you sign in.",
		NotMe:   "Ignore this email. Your password stays the same.",
	}.message(to)
}

// PasswordChanged is E3, sent whenever the account's own password changes.
func PasswordChanged(to string, when time.Time, zone string) Message {
	return email{
		Subject: "Your password was changed",
		Lines:   []string{"The password of your Guardian account was changed. Other sessions were signed out."},
		Facts:   []fact{{"When", When(when, zone)}},
		NotMe:   "Reset your password from the sign-in page, or ask your administrator for a temporary one.",
	}.message(to)
}

// EmailChanging is E5, sent to the old address when the account asks to move to a new one.
func EmailChanging(to, newAddress string, when time.Time, zone string) Message {
	return email{
		Subject: "Your email address is being changed",
		Lines: []string{"Your Guardian account is moving to a new email address. " +
			"This address stops getting emails once the new one is confirmed."},
		Facts: []fact{{"New address", Mask(newAddress)}, {"When", When(when, zone)}},
		NotMe: "Change your password now and sign out everywhere else. Then tell your administrator.",
	}.message(to)
}
