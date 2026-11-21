package backup

import (
	"testing"

	"filippo.io/age"
)

// newKey returns an age key pair: the public key (recipient) and the private key (identity).
func newKey(t testing.TB) (recipient, identity string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.Recipient().String(), id.String()
}
