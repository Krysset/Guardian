package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) with the parameters every authenticator app supports: SHA-1, 6 digits, 30 seconds.

const (
	totpPeriod = 30
	totpDigits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a new 160-bit secret in base32, as authenticator apps expect it.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// TOTPStep is the 30-second time step a moment falls in.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// TOTPCode is the code for a secret at a time step.
func TOTPCode(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1_000_000), nil
}

// NormalizeCode removes the spaces people type into codes ("482 913").
func NormalizeCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, strings.TrimSpace(code))
}

// VerifyTOTP checks a code against the steps around now (one step of clock drift either way) and returns
// the step it matched. A step at or before lastStep is refused, so a code works only once.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = NormalizeCode(code)
	if len(code) != totpDigits {
		return 0, false
	}
	current := TOTPStep(now)
	for _, step := range []int64{current, current - 1, current + 1} {
		if step <= lastStep {
			continue
		}
		want, err := TOTPCode(secret, step)
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// OTPAuthURI is what the QR code holds: the secret, and the names the app shows for the entry.
func OTPAuthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// GroupSecret writes a secret in groups of four, for typing in by hand: "JBSW Y3DP EHPK 3PXP ...".
func GroupSecret(secret string) string {
	var parts []string
	for len(secret) > 4 {
		parts = append(parts, secret[:4])
		secret = secret[4:]
	}
	return strings.Join(append(parts, secret), " ")
}

// Recovery codes: 8 characters from an alphabet without look-alikes (no i, l, o, u), written xxxx-xxxx.
const recoveryAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"

// RecoveryCodeCount is how many recovery codes an account gets.
const RecoveryCodeCount = 10

// NewRecoveryCodes returns RecoveryCodeCount new codes.
func NewRecoveryCodes() ([]string, error) {
	codes := make([]string, RecoveryCodeCount)
	for i := range codes {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		for j := range b {
			b[j] = recoveryAlphabet[b[j]&31]
		}
		codes[i] = string(b[:4]) + "-" + string(b[4:])
	}
	return codes, nil
}

// NormalizeRecoveryCode turns what someone typed into the stored form: lower case, no spaces or dashes,
// and the look-alikes mapped (i and l to 1, o to 0).
func NormalizeRecoveryCode(code string) string {
	code = strings.ToLower(NormalizeCode(code))
	return strings.NewReplacer("i", "1", "l", "1", "o", "0", "u", "v").Replace(code)
}

// HashRecoveryCode is what is stored for a recovery code. The account id makes equal codes of two accounts
// hash differently.
func HashRecoveryCode(accountID, code string) string {
	sum := sha256.Sum256([]byte(accountID + ":" + NormalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}
