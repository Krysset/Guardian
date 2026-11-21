package web

// Proof of work (ALTCHA-style). A form that bots like carries a puzzle: a salt and the SHA-256 of the salt
// followed by a secret number from 0 to PoWMax. The browser's script finds the number by trying them all
// (about half a second), and sends it with the form. A person barely notices; a bot pays for every
// attempt. The puzzle travels sealed with the keyring, so every replica can check it, and each one is
// accepted once.
//
// Where: always on sign-up (the page and /api/v1/signup) and forgot-password, and on sign-in once an
// address has failed PoWAfterFailures times. Without JavaScript the puzzle cannot be solved, so those
// forms explain that; signing in stays possible until an address fails repeatedly.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"guardian/internal/httpx"
	db "guardian/internal/store"
)

var (
	// PoWMax is the largest secret number. The browser tries half of them on average: about a third of a
	// second on a laptop, a second or two on an older phone, and it starts when the page opens. Tests set it
	// low.
	PoWMax = 50000
	// PoWAfterFailures is how many failed sign-ins from an address make its sign-in form carry a puzzle.
	PoWAfterFailures = 3
)

// powLifetime is how long a puzzle may be answered: long enough to fill in a form slowly.
const powLifetime = 30 * time.Minute

// PoW is a puzzle as a page or the API hands it out.
type PoW struct {
	Algorithm string `json:"algorithm"` // always SHA-256
	Salt      string `json:"salt"`
	Challenge string `json:"challenge"` // hex SHA-256 of salt + the number in decimal
	Max       int    `json:"max"`
	Token     string `json:"token"` // the sealed puzzle, sent back with the answer
}

type sealedPoW struct {
	Salt      string `json:"s"`
	Challenge string `json:"c"`
	Expires   int64  `json:"e"`
}

// NewPoW makes a puzzle.
func NewPoW() (PoW, error) {
	salt := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return PoW{}, err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(PoWMax)+1))
	if err != nil {
		return PoW{}, err
	}
	p := PoW{Algorithm: "SHA-256", Salt: hex.EncodeToString(salt), Max: PoWMax}
	p.Challenge = powHash(p.Salt, n.String())
	if p.Token, err = seal(sealedPoW{p.Salt, p.Challenge, time.Now().Add(powLifetime).Unix()}); err != nil {
		return PoW{}, err
	}
	return p, nil
}

func powHash(salt, number string) string {
	sum := sha256.Sum256([]byte(salt + number))
	return hex.EncodeToString(sum[:])
}

var (
	// ErrPoWMissing: no answer came with the form, as from a browser without JavaScript.
	ErrPoWMissing = errors.New("the form came without the answer to its puzzle")
	// ErrPoWInvalid: a wrong, expired or already used answer.
	ErrPoWInvalid = errors.New("the answer to the form's puzzle is wrong, expired or used already")
)

var powChecks = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "guardian", Name: "pow_checks_total",
	Help: "Proof-of-work answers checked, by form (signup, forgot, login, api_signup) and result: passed, " +
		"missing (no answer, as without JavaScript) or invalid (wrong, expired or reused).",
}, []string{"form", "result"})

func init() {
	for _, f := range []string{"signup", "forgot", "login", "api_signup"} {
		for _, r := range []string{"passed", "missing", "invalid"} {
			powChecks.WithLabelValues(f, r)
		}
	}
}

// CheckPoW checks the answer to a puzzle: the sealed token and the number found. form names the form for
// the metric.
func CheckPoW(form, token, number string) error {
	result := "invalid"
	defer func() { powChecks.WithLabelValues(form, result).Inc() }()
	if token == "" || number == "" {
		result = "missing"
		return ErrPoWMissing
	}
	var p sealedPoW
	if len(number) > 12 || !unseal(token, &p) || time.Now().Unix() > p.Expires {
		return ErrPoWInvalid
	}
	if _, err := strconv.ParseUint(number, 10, 64); err != nil || powHash(p.Salt, number) != p.Challenge {
		return ErrPoWInvalid
	}
	fresh, err := db.UseChallenge("pow:"+p.Challenge, time.Unix(p.Expires, 0))
	if err != nil || !fresh {
		return ErrPoWInvalid
	}
	result = "passed"
	return nil
}

// checkFormPoW checks a form's puzzle (fields pow and pow_number) and returns the message to show when it
// fails, or "".
func checkFormPoW(r *http.Request, form string) string {
	switch err := CheckPoW(form, r.PostFormValue("pow"), strings.TrimSpace(r.PostFormValue("pow_number"))); {
	case err == nil:
		return ""
	case errors.Is(err, ErrPoWMissing):
		return "This form needs JavaScript, which checks that a person and not a program sends it. Turn it on and try again."
	default:
		return "The check that a person sends this form failed or took too long. Try again."
	}
}

// loginNeedsPoW reports whether sign-in from this request's address must answer a puzzle.
func loginNeedsPoW(r *http.Request) bool {
	n, err := db.RateLimitCount("login:ip:"+httpx.ClientIP(r), loginLimits.Window)
	return err == nil && n >= PoWAfterFailures
}
