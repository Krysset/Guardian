package auth

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func testKey(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Setenv("KEY_ENCRYPTION_KEY", testKey(1))
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
	t.Setenv("KEY_ENCRYPTION_KEY", testKey(1))
	a, _ := encrypt([]byte("same"))
	b, _ := encrypt([]byte("same"))
	if a == b {
		t.Fatal("identical ciphertexts: nonce is reused")
	}
}

func TestDecryptFailsWithWrongKeyOrTampering(t *testing.T) {
	t.Setenv("KEY_ENCRYPTION_KEY", testKey(1))
	enc, _ := encrypt([]byte("secret"))

	t.Setenv("KEY_ENCRYPTION_KEY", testKey(2))
	if _, err := decrypt(enc); err == nil {
		t.Error("decrypting with a different key must fail")
	}

	t.Setenv("KEY_ENCRYPTION_KEY", testKey(1))
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
	cases := map[string]string{
		"missing":      "",
		"not base64":   "%%%",
		"16 bytes":     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)),
		"64 bytes":     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64)),
	}
	for name, v := range cases {
		t.Setenv("KEY_ENCRYPTION_KEY", v)
		if _, err := encrypt([]byte("x")); err == nil {
			t.Errorf("%s: encrypt must fail without a valid 32-byte key", name)
		}
	}
}
