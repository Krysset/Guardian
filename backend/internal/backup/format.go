// Package backup writes and reads Guardian backups.
//
// A backup is one file in three parts:
//
//	GUARDIAN-BACKUP 1\n                        magic line with the format version
//	{"format":1,...}\n                         the manifest: JSON on one line, in the clear, no personal data
//	<payload>                                  the rows; encrypted with age unless decrypted for a restore
//	GUARDIAN-BACKUP-END size=<20 digits> sha256=<64 hex>\n
//
// The payload is gzip-compressed JSON, one object per row: {"t":"<table>","r":<row_to_json>}. The trailer
// carries the payload's size and SHA-256, so `guardian backup verify` can check a file without the private
// key. They come last because the backup is streamed to stdout (kubectl exec) and is not known until the
// end. age authenticates the payload on its own; the trailer catches truncation and damage in storage.
package backup

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"time"
)

// FormatVersion is the version of the file format, on the magic line and in the manifest.
const FormatVersion = 1

const (
	magic         = "GUARDIAN-BACKUP 1\n"
	trailerPrefix = "GUARDIAN-BACKUP-END size="
	trailerLen    = len(trailerPrefix) + 20 + len(" sha256=") + 64 + 1

	// EncryptionAge marks a payload encrypted with age; EncryptionNone one decrypted for a restore.
	EncryptionAge  = "age"
	EncryptionNone = "none"
)

// Manifest describes a backup. It is stored in the clear, so it holds no personal data: counts, times and
// identifiers only.
type Manifest struct {
	Format int `json:"format"`
	// SchemaRevision is the fingerprint of the migration 1 that created the database. Until 1.0 a backup
	// only restores into a database with the same revision.
	SchemaRevision string    `json:"schema_revision"`
	CreatedAt      time.Time `json:"created_at"`
	Issuer         string    `json:"issuer"`
	// KeyringKeys are the encryption-keyring keys the backed-up secrets (signing keys, authenticator apps)
	// are encrypted with, as "<key id>:<fingerprint>". A restore needs every one of them in its keyring.
	KeyringKeys []string `json:"keyring_keys"`
	Encryption  string   `json:"encryption"`
	// Recipients are the age public keys the payload is encrypted to.
	Recipients       []string     `json:"recipients,omitempty"`
	AuditLogIncluded bool         `json:"audit_log_included"`
	Tables           []TableCount `json:"tables"`
}

// TableCount is the number of rows of one table in a backup.
type TableCount struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

// Rows returns the number of rows of a table, and whether the manifest lists it.
func (m Manifest) Rows(table string) (int64, bool) {
	for _, t := range m.Tables {
		if t.Name == table {
			return t.Rows, true
		}
	}
	return 0, false
}

// Writer writes a backup file. Write the payload, then Close to add the trailer.
type Writer struct {
	w      io.Writer
	hash   hash.Hash
	size   int64
	closed bool
}

// NewWriter writes the magic line and the manifest to w and returns a writer for the payload.
func NewWriter(w io.Writer, m Manifest) (*Writer, error) {
	m.Format = FormatVersion
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, magic); err != nil {
		return nil, err
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	return &Writer{w: w, hash: sha256.New()}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.hash.Write(p[:n])
	w.size += int64(n)
	return n, err
}

// Close writes the trailer. It does not close the underlying writer.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	_, err := io.WriteString(w.w, trailer(w.size, w.hash.Sum(nil)))
	return err
}

// Sum returns the payload's size and SHA-256 (hex) once the writer is closed.
func (w *Writer) Sum() (int64, string) { return w.size, hex.EncodeToString(w.hash.Sum(nil)) }

func trailer(size int64, sum []byte) string {
	return fmt.Sprintf("%s%020d sha256=%s\n", trailerPrefix, size, hex.EncodeToString(sum))
}

// ErrDamaged means the file is not a complete Guardian backup, or its payload does not match its trailer.
var ErrDamaged = errors.New("the backup file is damaged or incomplete")

// Reader reads a backup file. Read the payload to its end, then call Check.
type Reader struct {
	Manifest Manifest
	src      *bufio.Reader
	buf      []byte // read ahead but not yet returned; the last trailerLen bytes may be the trailer
	eof      bool
	hash     hash.Hash
	size     int64
	checked  error
	done     bool
}

// NewReader reads the magic line and the manifest.
func NewReader(r io.Reader) (*Reader, error) {
	src := bufio.NewReaderSize(r, 64<<10)
	line, err := src.ReadString('\n')
	if err != nil || line != magic {
		if len(line) > 16 && line[:16] == "GUARDIAN-BACKUP " {
			return nil, fmt.Errorf("this backup has format %q; this Guardian reads format %d", line[16:len(line)-1], FormatVersion)
		}
		return nil, errors.New("not a Guardian backup (the first line is wrong)")
	}
	line, err = src.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("%w: no manifest", ErrDamaged)
	}
	var m Manifest
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return nil, fmt.Errorf("%w: unreadable manifest: %v", ErrDamaged, err)
	}
	if m.Format != FormatVersion {
		return nil, fmt.Errorf("this backup has format %d; this Guardian reads format %d", m.Format, FormatVersion)
	}
	if m.Encryption != EncryptionAge && m.Encryption != EncryptionNone {
		return nil, fmt.Errorf("%w: unknown encryption %q", ErrDamaged, m.Encryption)
	}
	return &Reader{Manifest: m, src: src, hash: sha256.New()}, nil
}

// Read returns payload bytes. It holds back the last bytes of the file, which are the trailer.
func (r *Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for !r.eof && len(r.buf) < len(p)+trailerLen {
		chunk := make([]byte, max(len(p)+trailerLen-len(r.buf), 32<<10))
		n, err := r.src.Read(chunk)
		r.buf = append(r.buf, chunk[:n]...)
		if errors.Is(err, io.EOF) {
			r.eof = true
		} else if err != nil {
			return 0, err
		}
	}
	avail := len(r.buf) - trailerLen
	if avail <= 0 {
		if r.eof {
			r.finish()
			return 0, io.EOF
		}
		return 0, nil
	}
	n := copy(p, r.buf[:avail])
	r.hash.Write(p[:n])
	r.size += int64(n)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *Reader) finish() {
	if r.done {
		return
	}
	r.done = true
	if len(r.buf) < trailerLen || !bytes.HasPrefix(r.buf, []byte(trailerPrefix)) {
		r.checked = fmt.Errorf("%w: the end of the file is missing", ErrDamaged)
		return
	}
	t := string(r.buf)
	size, err := strconv.ParseInt(t[len(trailerPrefix):len(trailerPrefix)+20], 10, 64)
	if err != nil || t != trailer(size, mustHex(t[trailerLen-65:trailerLen-1])) {
		r.checked = fmt.Errorf("%w: the last line is not a valid trailer", ErrDamaged)
		return
	}
	if size != r.size || t != trailer(r.size, r.hash.Sum(nil)) {
		r.checked = fmt.Errorf("%w: the content does not match its checksum (size %d, expected %d)", ErrDamaged, r.size, size)
	}
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// Check reads whatever is left of the payload and compares it with the trailer.
func (r *Reader) Check() error {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	r.finish()
	return r.checked
}

// Sum returns the payload's size and SHA-256 (hex), valid after Check.
func (r *Reader) Sum() (int64, string) { return r.size, hex.EncodeToString(r.hash.Sum(nil)) }
