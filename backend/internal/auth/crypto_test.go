package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func keyB64(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

// useRing makes a keyring from spec the keyring for one test.
func useRing(t *testing.T, spec string) *Keyring {
	t.Helper()
	previous := CurrentKeyring()
	t.Cleanup(func() { SetKeyring(previous) })
	r, err := ParseKeyring(spec)
	if err != nil {
		t.Fatal(err)
	}
	SetKeyring(r)
	return r
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	useRing(t, "k1:"+keyB64(1))
	plain := []byte("-----BEGIN PRIVATE KEY----- pretend -----END PRIVATE KEY-----")
	enc, err := Encrypt(plain, AAD("signing_key", "private_key_encrypted", "abc"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(enc, "PRIVATE") || !strings.HasPrefix(enc, "v1:k1:") || KeyIDOf(enc) != "k1" {
		t.Fatalf("value = %s", enc)
	}
	got, err := Decrypt(enc, AAD("signing_key", "private_key_encrypted", "abc"))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := Decrypt(enc, AAD("signing_key", "private_key_encrypted", "other-row")); err == nil {
		t.Fatal("a value moved to another row decrypted")
	}
	a, _ := Encrypt([]byte("same"), "x")
	b, _ := Encrypt([]byte("same"), "x")
	if a == b {
		t.Fatal("identical ciphertexts: the nonce is reused")
	}
}

func TestRotatingTheKeyring(t *testing.T) {
	useRing(t, "k1:"+keyB64(1))
	old, _ := Encrypt([]byte("secret"), "x")

	// Step 1: the new key is added at the end; it decrypts only, the old one still encrypts.
	useRing(t, "k1:"+keyB64(1)+", k2:"+keyB64(2))
	if v, _ := Encrypt([]byte("secret"), "x"); KeyIDOf(v) != "k1" {
		t.Error("a key added at the end must not encrypt yet")
	}
	// Step 2: promoted to the front, it encrypts; old values still decrypt.
	useRing(t, "k2:"+keyB64(2)+"\nk1:"+keyB64(1))
	if v, _ := Encrypt([]byte("secret"), "x"); KeyIDOf(v) != "k2" {
		t.Error("the first key must encrypt")
	}
	if got, err := Decrypt(old, "x"); err != nil || string(got) != "secret" {
		t.Errorf("an old value: %v", err)
	}
	// Step 3: without the old key, old values fail with a clear error.
	useRing(t, "k2:"+keyB64(2))
	if _, err := Decrypt(old, "x"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("a value under a removed key: %v", err)
	}
	// The same id with other key material fails too.
	useRing(t, "k1:"+keyB64(9))
	if _, err := Decrypt(old, "x"); err == nil {
		t.Error("a value decrypted with other key material")
	}
}

func TestParseKeyringRefusesBadInput(t *testing.T) {
	for _, spec := range []string{"", "  ,  ", "k1", "k1:short", "K1:" + keyB64(1), "k1:" + keyB64(1) + ",k1:" + keyB64(2), ":" + keyB64(1)} {
		if _, err := ParseKeyring(spec); err == nil {
			t.Errorf("accepted %q", spec)
		} else if strings.Contains(err.Error(), keyB64(1)) {
			t.Errorf("the error shows the key: %v", err)
		}
	}
	r, err := ParseKeyring("k2:" + keyB64(2) + ",k1:" + keyB64(1))
	if err != nil || r.Primary().ID != "k2" || len(r.Keys()) != 2 || r.Fingerprints()["k1"] == r.Fingerprints()["k2"] {
		t.Errorf("ring = %+v, %v", r, err)
	}
}

func TestSealedValuesAreNotStoredValues(t *testing.T) {
	useRing(t, "k1:"+keyB64(1))
	s, _ := Seal([]byte("flow"))
	if _, err := Decrypt(s, AAD("account_mfa", "secret", "x")); err == nil {
		t.Error("a sealed token decrypted as a stored value")
	}
	if got, err := Open(s); err != nil || string(got) != "flow" {
		t.Errorf("open: %v", err)
	}
}
