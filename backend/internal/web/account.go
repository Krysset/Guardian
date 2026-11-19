package web

import (
	"errors"
	"net/http"
	"regexp"
	"time"

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
// count towards the per-address limit, so typos in the form do not use it up.
func CreateAccount(r *http.Request, username, password string) (db.Account, error) {
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
		httpx.RateLimited.WithLabelValues("register").Inc()
		return db.Account{}, ErrTooManySignups
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return db.Account{}, err
	}
	acct, err := db.CreateAccount(username, hash)
	if db.IsUniqueViolation(err) {
		return db.Account{}, ErrUsernameTaken
	}
	if err != nil {
		return db.Account{}, err
	}
	db.Audit("account.signed_up", acct.ID, "", httpx.ClientIP(r), nil)
	return acct, nil
}
