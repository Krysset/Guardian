// Package passkey holds security keys and passkeys (WebAuthn, through go-webauthn/webauthn).
//
// A key is used in one of three ways:
//   - as the second factor after the password (V7): any of the account's keys;
//   - to sign in without a password (V8): a passkey, found from the browser's own list. The authenticator
//     must verify the user (PIN, fingerprint, face), so a passkey alone is two factors and the session counts
//     as having passed two-factor;
//   - to confirm it's you before a protected change (U16).
//
// Each ceremony's state (the challenge) travels sealed with the key encryption key, in a token the page or
// the API client sends back, so nothing waits in the database between the two steps. A token names its
// kind and account, so one begun for one purpose cannot finish another.
package passkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"guardian/internal/auth"
	db "guardian/internal/store"
)

// Timeout is how long the browser waits for the key, and how long a begun ceremony stays valid.
const Timeout = 5 * time.Minute

var wa *webauthn.WebAuthn

// Configure sets the relying party: its id is the issuer's host name, so keys work on every port and path
// of it. origins are the browser origins allowed to use the keys: the issuer's, and the management UI's when
// it is served elsewhere (ALLOWED_ORIGINS, as in local development).
func Configure(issuerURL string, origins []string, siteName string) error {
	u, err := url.Parse(issuerURL)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("passkeys need the issuer's host name: %q", issuerURL)
	}
	all := []string{u.Scheme + "://" + u.Host}
	for _, o := range origins {
		if o != all[0] {
			all = append(all, o)
		}
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: siteName,
		RPOrigins:     all,
		// No attestation: Guardian accepts any authenticator, so it has nothing to check one against.
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// A passkey where the authenticator can store one; a plain security key otherwise.
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: Timeout, TimeoutUVD: Timeout},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: Timeout, TimeoutUVD: Timeout},
		},
	})
	if err != nil {
		return err
	}
	wa = w
	return nil
}

var (
	// ErrExpired means the token is unknown, expired, or was begun for something else; start again.
	ErrExpired = errors.New("the security key request has expired; try again")
	// ErrNotRecognised means the key's answer did not check out: an unknown key, a wrong signature, a
	// key that may have been copied.
	ErrNotRecognised = errors.New("the security key was not recognised")
	// ErrNoKeys means the account has no security keys.
	ErrNoKeys = errors.New("the account has no security keys")
	// ErrOff means Configure failed, so security keys cannot be used.
	ErrOff = errors.New("security keys and passkeys are not configured")
)

// user is an account as the library sees it. The user handle is the account's id (16 bytes): it is stored
// on passkeys, so it must say nothing about the person.
type user struct {
	id            []byte
	name, display string
	creds         []webauthn.Credential
	rows          []db.StoredKey
}

func (u *user) WebAuthnID() []byte                         { return u.id }
func (u *user) WebAuthnName() string                       { return u.name }
func (u *user) WebAuthnDisplayName() string                { return u.display }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func loadUser(accountID string) (*user, error) {
	acct, err := db.GetAccount(accountID)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(acct.ID)
	if err != nil {
		return nil, err
	}
	u := &user{id: id[:], name: acct.Username, display: acct.Username}
	if acct.DisplayName != "" {
		u.display = acct.DisplayName
	}
	if u.rows, err = db.ListSecurityKeys(acct.ID); err != nil {
		return nil, err
	}
	for _, row := range u.rows {
		var c webauthn.Credential
		if err := json.Unmarshal(row.Credential, &c); err != nil {
			return nil, err
		}
		u.creds = append(u.creds, c)
	}
	return u, nil
}

// ceremony is a begun ceremony, sealed into its token.
type ceremony struct {
	Kind    string               `json:"k"` // register, login, passkey
	Account string               `json:"a,omitempty"`
	Session webauthn.SessionData `json:"s"`
}

func sealCeremony(c ceremony) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return auth.Seal("passkey", b)
}

func openCeremony(token, kind, accountID string) (ceremony, error) {
	var c ceremony
	if wa == nil {
		return c, ErrOff
	}
	b, err := auth.Open("passkey", token)
	if err != nil || json.Unmarshal(b, &c) != nil || c.Kind != kind || c.Account != accountID ||
		time.Now().After(c.Session.Expires) {
		return ceremony{}, ErrExpired
	}
	// Each challenge is answered once: a copied answer cannot be sent again.
	if first, err := db.UseChallenge(c.Session.Challenge, c.Session.Expires); err != nil {
		return ceremony{}, err
	} else if !first {
		return ceremony{}, ErrExpired
	}
	return c, nil
}

func options(v any, s *webauthn.SessionData, kind, accountID string) (json.RawMessage, string, error) {
	opts, err := json.Marshal(v)
	if err != nil {
		return nil, "", err
	}
	token, err := sealCeremony(ceremony{Kind: kind, Account: accountID, Session: *s})
	return opts, token, err
}

// BeginRegistration starts adding a key to the account. The options go to navigator.credentials.create;
// the token comes back with its answer. The account's own keys are excluded, so one key is not added twice.
func BeginRegistration(accountID string) (json.RawMessage, string, error) {
	if wa == nil {
		return nil, "", ErrOff
	}
	u, err := loadUser(accountID)
	if err != nil {
		return nil, "", err
	}
	exclude := make([]protocol.CredentialDescriptor, len(u.creds))
	for i, c := range u.creds {
		exclude[i] = c.Descriptor()
	}
	creation, s, err := wa.BeginRegistration(u, webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, "", err
	}
	return options(creation, s, "register", accountID)
}

// NewKey is a checked new key, ready to store.
type NewKey struct {
	ID         []byte
	Credential []byte // JSON
	SignCount  uint32
}

// FinishRegistration checks the browser's answer to BeginRegistration. Nothing is stored here.
func FinishRegistration(accountID, token string, response []byte) (NewKey, error) {
	c, err := openCeremony(token, "register", accountID)
	if err != nil {
		return NewKey{}, err
	}
	u, err := loadUser(accountID)
	if err != nil {
		return NewKey{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return NewKey{}, ErrNotRecognised
	}
	cred, err := wa.CreateCredential(u, c.Session, parsed)
	if err != nil {
		return NewKey{}, ErrNotRecognised
	}
	b, err := json.Marshal(cred)
	return NewKey{ID: cred.ID, Credential: b, SignCount: cred.Authenticator.SignCount}, err
}

// BeginLogin asks for one of the account's keys: the second factor at sign-in, or confirming it's you.
func BeginLogin(accountID string) (json.RawMessage, string, error) {
	if wa == nil {
		return nil, "", ErrOff
	}
	u, err := loadUser(accountID)
	if err != nil {
		return nil, "", err
	}
	if len(u.creds) == 0 {
		return nil, "", ErrNoKeys
	}
	assertion, s, err := wa.BeginLogin(u)
	if err != nil {
		return nil, "", err
	}
	return options(assertion, s, "login", accountID)
}

// FinishLogin checks the answer to BeginLogin, records the key's use, and returns the key's name.
func FinishLogin(accountID, token string, response []byte) (string, error) {
	c, err := openCeremony(token, "login", accountID)
	if err != nil {
		return "", err
	}
	u, err := loadUser(accountID)
	if err != nil {
		return "", err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return "", ErrNotRecognised
	}
	cred, err := wa.ValidateLogin(u, c.Session, parsed)
	if err != nil {
		return "", ErrNotRecognised
	}
	return recordUse(u, cred)
}

// BeginPasskeyLogin asks the browser for any passkey of this site, to sign in without a password. The
// authenticator must verify the user.
func BeginPasskeyLogin() (json.RawMessage, string, error) {
	if wa == nil {
		return nil, "", ErrOff
	}
	assertion, s, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", err
	}
	return options(assertion, s, "passkey", "")
}

// FinishPasskeyLogin checks the answer to BeginPasskeyLogin and returns the account it signs in. The
// account's status is the caller's to check.
func FinishPasskeyLogin(token string, response []byte) (accountID string, keyName string, err error) {
	c, err := openCeremony(token, "passkey", "")
	if err != nil {
		return "", "", err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return "", "", ErrNotRecognised
	}
	var found *user
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		owner, err := db.AccountForCredential(rawID)
		if err != nil {
			return nil, err
		}
		id, err := uuid.Parse(owner)
		if err != nil || !bytes.Equal(id[:], userHandle) {
			return nil, ErrNotRecognised
		}
		if found, err = loadUser(owner); err != nil {
			return nil, err
		}
		return found, nil
	}
	_, cred, err := wa.ValidatePasskeyLogin(handler, c.Session, parsed)
	if err != nil || found == nil {
		return "", "", ErrNotRecognised
	}
	id, _ := uuid.FromBytes(found.id)
	name, err := recordUse(found, cred)
	return id.String(), name, err
}

// keyName is the name the account gave the key with this credential id.
func keyName(u *user, credentialID []byte) string {
	for _, row := range u.rows {
		var stored webauthn.Credential
		if json.Unmarshal(row.Credential, &stored) == nil && bytes.Equal(stored.ID, credentialID) {
			return row.Name
		}
	}
	return ""
}

// cloneWarnings should stay at 0: each one is a security key that may have been copied.
var cloneWarnings = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: "guardian", Name: "passkey_clone_warnings_total",
	Help: "Security key or passkey uses refused because the key's counter went backwards, which means the key may " +
		"have been copied. Should stay at 0; the audit log has which account. Synced passkeys never trigger it.",
})

// recordUse stores the key's new counter and flags. A counter that went backwards means the key may have
// been copied: the use is refused (synced passkeys keep their counter at 0 and never trip this).
func recordUse(u *user, cred *webauthn.Credential) (string, error) {
	if cred.Authenticator.CloneWarning {
		cloneWarnings.Inc()
		accountID := ""
		if id, err := uuid.FromBytes(u.id); err == nil {
			accountID = id.String()
		}
		db.Audit("mfa.key_clone_warning", accountID, "", "", map[string]any{"key": keyName(u, cred.ID)})
		return "", ErrNotRecognised
	}
	for _, row := range u.rows {
		var stored webauthn.Credential
		if json.Unmarshal(row.Credential, &stored) == nil && bytes.Equal(stored.ID, cred.ID) {
			b, err := json.Marshal(cred)
			if err != nil {
				return "", err
			}
			return row.Name, db.UseSecurityKey(row.ID, b, cred.Authenticator.SignCount)
		}
	}
	return "", ErrNotRecognised
}
