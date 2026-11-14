package auth

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// useKey makes the given 32-byte key (every byte = b) the encryption key for one test.
func useKey(t *testing.T, b byte) {
	t.Helper()
	previous := encryptionKey
	t.Cleanup(func() { encryptionKey = previous })
	if err := SetEncryptionKey(bytes.Repeat([]byte{b}, 32)); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	useKey(t, 1)
	plain := []byte("-----BEGIN PRIVATE KEY----- pretend -----END PRIVATE KEY-----")
	enc, err := encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(enc, "PRIVATE") {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := decrypt(enc)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestEncryptUsesFreshNonce(t *testing.T) {
	useKey(t, 1)
	a, _ := encrypt([]byte("same"))
	b, _ := encrypt([]byte("same"))
	if a == b {
		t.Fatal("identical ciphertexts: nonce is reused")
	}
}

func TestDecryptFailsWithWrongKeyOrTampering(t *testing.T) {
	useKey(t, 1)
	enc, _ := encrypt([]byte("secret"))

	useKey(t, 2)
	if _, err := decrypt(enc); err == nil {
		t.Error("decrypting with a different key must fail")
	}

	useKey(t, 1)
	raw, _ := base64.StdEncoding.DecodeString(enc)
	raw[len(raw)-1] ^= 0xff
	if _, err := decrypt(base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Error("tampered ciphertext must fail authentication")
	}
	if _, err := decrypt("AAAA"); err == nil {
		t.Error("too-short ciphertext must fail")
	}
	if _, err := decrypt("%%%not base64%%%"); err == nil {
		t.Error("invalid base64 must fail")
	}
}

func TestEncryptionKeyValidation(t *testing.T) {
	previous := encryptionKey
	t.Cleanup(func() { encryptionKey = previous })

	encryptionKey = nil
	if _, err := encrypt([]byte("x")); err == nil {
		t.Error("encrypt must fail when no key is set")
	}
	for _, size := range []int{0, 16, 31, 64} {
		if err := SetEncryptionKey(bytes.Repeat([]byte{1}, size)); err == nil {
			t.Errorf("a %d-byte key must be rejected", size)
		}
	}
	if encryptionKey != nil {
		t.Error("a rejected key must not be stored")
	}
}
