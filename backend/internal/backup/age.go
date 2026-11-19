// Package backup writes and restores Guardian's backups (release 0.2). Backups are always encrypted with age
// (https://age-encryption.org) to a public key; the private key stays offline.
package backup

import (
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
)

// Encrypt returns a writer that encrypts everything written to it for the given age public keys (one per
// line, as in an age recipients file) and writes the result to dst. Close it to finish the file.
func Encrypt(dst io.Writer, recipients string) (io.WriteCloser, error) {
	rs, err := age.ParseRecipients(strings.NewReader(recipients))
	if err != nil {
		return nil, fmt.Errorf("reading the backup public key: %w", err)
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("no backup public key given")
	}
	return age.Encrypt(dst, rs...)
}

// Decrypt returns a reader of the plaintext of an encrypted backup, using the age private keys (an age
// identity file).
func Decrypt(src io.Reader, identities io.Reader) (io.Reader, error) {
	ids, err := age.ParseIdentities(identities)
	if err != nil {
		return nil, fmt.Errorf("reading the backup private key: %w", err)
	}
	return age.Decrypt(src, ids...)
}
