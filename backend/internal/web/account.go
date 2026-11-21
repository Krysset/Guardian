package web

import (
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	db "guardian/internal/store"
)

// The rules for usernames and passwords, shared by the sign-in pages and /api/v1.
var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

const (
	UsernameRule = "username must be 3-64 characters: letters, digits, '.', '_' or '-'"
	PasswordRule = "The password must be 10-1024 characters"
)

// ValidUsername reports whether u follows UsernameRule. Usernames never contain "@", so a login that
// does is an email address.
func ValidUsername(u string) bool { return usernameRe.MatchString(u) }

// ValidEmail accepts a bare address such as alice@example.com, nothing else ("Alice <a@b>" is refused).
func ValidEmail(s string) bool {
	if len(s) > 254 {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == ""
}

// ValidPassword reports whether p follows PasswordRule. The upper bound protects the hasher from huge inputs.
func ValidPassword(p string) bool { return len(p) >= 10 && len(p) <= 1024 }

const (
	signupLimit  = 10 // sign-ups per IP per window
	signupWindow = time.Hour
)

// SignupWindow is how long a client must wait after ErrTooManySignups.
const SignupWindow = signupWindow

var (
	ErrUsernameRule   = errors.New(UsernameRule)
	ErrPasswordRule   = errors.New(PasswordRule)
	ErrUsernameTaken  = errors.New("That username is already taken")
	ErrTooManySignups = errors.New("Too many sign-ups from this address. Try again later.")
)

// CreateAccount is open sign-up, for the sign-up page and POST /api/v1/signup alike. Only valid requests
// count towards the per-address limit, so typos in the form do not use it up. A pending account waits for
// its email address to be confirmed before it can sign in.
func CreateAccount(r *http.Request, username, password string, pending bool) (db.Account, error) {
	if !ValidUsername(username) {
		return db.Account{}, ErrUsernameRule
	}
	if !ValidPassword(password) {
		return db.Account{}, ErrPasswordRule
	}
	n, err := db.RateLimitHit("register:ip:"+httpx.ClientIP(r), signupWindow)
	if err != nil {
		return db.Account{}, err
	}
	if n > signupLimit {
		httpx.CountRefused("register")
		return db.Account{}, ErrTooManySignups
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return db.Account{}, err
	}
	create := db.CreateAccount
	if pending {
		create = db.CreatePendingAccount
	}
	acct, err := create(username, hash)
	if db.IsUniqueViolation(err) {
		return db.Account{}, ErrUsernameTaken
	}
	if err != nil {
		return db.Account{}, err
	}
	db.Audit("account.signed_up", acct.ID, "", httpx.ClientIP(r), nil)
	if pending {
		signups.WithLabelValues("awaiting_email").Inc()
	} else {
		signups.WithLabelValues("active").Inc()
	}
	return acct, nil
}

// signups counts self-service sign-ups. Accounts made by bots usually never confirm their address, so a
// growing gap between awaiting_email and confirmed is the sign of spam sign-ups (guardian_accounts{status=
// "pending"} shows the same from the other side, until unconfirmed sign-ups are cleaned up).
var signups = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "guardian", Name: "signups_total",
	Help: "Self-service sign-ups: awaiting_email (created, waiting for the link in the email), confirmed (the link " +
		"was followed) and active (created without an email address, usable at once).",
}, []string{"result"})

func init() {
	for _, r := range []string{"awaiting_email", "confirmed", "active"} {
		signups.WithLabelValues(r)
	}
}
