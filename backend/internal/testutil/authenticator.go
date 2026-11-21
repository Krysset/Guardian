package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sort"
)

// Authenticator is a software security key for tests: it answers the WebAuthn options Guardian sends the
// browser the way navigator.credentials.create and .get would, with ES256 keys and no attestation. Every
// credential it makes is a passkey (it stores the user handle) and it verifies the user.
type Authenticator struct {
	Origin string // the page's origin the browser would report
	// BackupEligible marks its credentials as synced passkeys (flags BE and BS).
	BackupEligible bool
	// FrozenCounter keeps the signature counter at 0, as synced passkeys do.
	FrozenCounter bool

	creds   []*softCredential
	counter uint32
}

type softCredential struct {
	ID         []byte
	RPID       string
	UserHandle []byte
	key        *ecdsa.PrivateKey
}

// NewAuthenticator returns an empty authenticator for pages served at origin.
func NewAuthenticator(origin string) *Authenticator { return &Authenticator{Origin: origin} }

// Forget drops the authenticator's credentials, like a lost key.
func (a *Authenticator) Forget() { a.creds = nil }

// SetCounter sets the signature counter the next answer counts up from (to fake a cloned key).
func (a *Authenticator) SetCounter(n uint32) { a.counter = n }

var b64 = base64.RawURLEncoding

type optionsJSON struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		RPID string `json:"rpId"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Allow []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
		Exclude []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

func (a *Authenticator) clientData(kind, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

func (a *Authenticator) flags(attested bool) byte {
	f := byte(0x01 | 0x04) // user present, user verified
	if a.BackupEligible {
		f |= 0x08 | 0x10
	}
	if attested {
		f |= 0x40
	}
	return f
}

func (a *Authenticator) nextCount() uint32 {
	if a.FrozenCounter {
		return 0
	}
	a.counter++
	return a.counter
}

// Create answers options from navigator.credentials.create with a new credential, as JSON.
func (a *Authenticator) Create(options []byte) ([]byte, error) {
	var o optionsJSON
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, err
	}
	for _, ex := range o.PublicKey.Exclude {
		for _, c := range a.creds {
			if b64.EncodeToString(c.ID) == ex.ID {
				return nil, errors.New("InvalidStateError: this authenticator is already registered")
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	userHandle, err := b64.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		return nil, err
	}
	c := &softCredential{ID: make([]byte, 32), RPID: o.PublicKey.RP.ID, UserHandle: userHandle, key: key}
	rand.Read(c.ID)
	a.creds = append(a.creds, c)

	pub, _ := key.PublicKey.ECDH()
	raw := pub.Bytes() // 0x04 || X || Y
	cose := cborMap(map[any]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
	auth := a.authData(c.RPID, true)
	auth = append(auth, make([]byte, 16)...) // AAGUID: none
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(c.ID)))
	auth = append(auth, c.ID...)
	auth = append(auth, cose...)
	attestation := cborMap(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": auth})
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(c.ID), "rawId": b64.EncodeToString(c.ID), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", o.PublicKey.Challenge)),
			"attestationObject": b64.EncodeToString(attestation),
			"transports":        []string{"usb"},
		},
	})
}

func (a *Authenticator) authData(rpID string, attested bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append(h[:], a.flags(attested))
	return binary.BigEndian.AppendUint32(out, a.nextCount())
}

// Get answers options from navigator.credentials.get: with allowCredentials, the first of its own that is
// allowed; without (a passkey sign-in), its first credential for the site.
func (a *Authenticator) Get(options []byte) ([]byte, error) {
	var o optionsJSON
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, err
	}
	var c *softCredential
	for _, cand := range a.creds {
		if cand.RPID != o.PublicKey.RPID {
			continue
		}
		if len(o.PublicKey.Allow) == 0 {
			c = cand
			break
		}
		for _, al := range o.PublicKey.Allow {
			if al.ID == b64.EncodeToString(cand.ID) {
				c = cand
			}
		}
		if c != nil {
			break
		}
	}
	if c == nil {
		return nil, errors.New("NotAllowedError: no credential for this site")
	}
	auth := a.authData(c.RPID, false)
	client := a.clientData("webauthn.get", o.PublicKey.Challenge)
	sum := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(c.ID), "rawId": b64.EncodeToString(c.ID), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(client),
			"authenticatorData": b64.EncodeToString(auth),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(c.UserHandle),
		},
	})
}

// ---- a minimal CBOR encoder: unsigned and negative integers, byte and text strings, maps ----

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	default:
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
	}
}

func cborValue(v any) []byte {
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return cborHead(0, uint64(x))
		}
		return cborHead(1, uint64(-1-x))
	case []byte:
		return append(cborHead(2, uint64(len(x))), x...)
	case string:
		return append(cborHead(3, uint64(len(x))), x...)
	case map[any]any:
		return cborMap(x)
	}
	panic("cbor: unsupported value")
}

// cborMap encodes a map with its keys in the canonical order (shorter encodings first, then bytewise).
func cborMap(m map[any]any) []byte {
	type kv struct{ k, v []byte }
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{cborValue(k), cborValue(v)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if len(pairs[i].k) != len(pairs[j].k) {
			return len(pairs[i].k) < len(pairs[j].k)
		}
		return string(pairs[i].k) < string(pairs[j].k)
	})
	out := cborHead(5, uint64(len(m)))
	for _, p := range pairs {
		out = append(append(out, p.k...), p.v...)
	}
	return out
}
