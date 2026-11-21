package backup

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func writeFile(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, Manifest{Encryption: EncryptionNone, Issuer: "https://auth.test", CreatedAt: time.Unix(0, 0).UTC(),
		Tables: []TableCount{{"account", 3}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func readFile(r io.Reader) (Manifest, []byte, error) {
	br, err := NewReader(r)
	if err != nil {
		return Manifest{}, nil, err
	}
	got, err := io.ReadAll(br)
	if err != nil {
		return br.Manifest, nil, err
	}
	return br.Manifest, got, br.Check()
}

func TestFormatRoundTripsAndHoldsBackTheTrailer(t *testing.T) {
	for _, size := range []int{0, 1, trailerLen - 1, trailerLen, trailerLen + 1, 100_000} {
		payload := bytes.Repeat([]byte{0, 'x', '\n', 0xff}, size/4+1)[:size]
		file := writeFile(t, payload)
		if !bytes.HasPrefix(file, []byte("GUARDIAN-BACKUP 1\n{\"format\":1,")) {
			t.Fatalf("file starts with %q", file[:40])
		}
		for name, r := range map[string]io.Reader{
			"whole":    bytes.NewReader(file),
			"one byte": iotest.OneByteReader(bytes.NewReader(file)),
			"halves":   iotest.HalfReader(bytes.NewReader(file)),
		} {
			m, got, err := readFile(r)
			if err != nil {
				t.Fatalf("size %d, %s: %v", size, name, err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("size %d, %s: payload differs (got %d bytes)", size, name, len(got))
			}
			if n, _ := m.Rows("account"); n != 3 || m.Issuer != "https://auth.test" || m.Format != FormatVersion {
				t.Fatalf("manifest = %+v", m)
			}
		}
	}
}

func TestFormatDetectsDamage(t *testing.T) {
	file := writeFile(t, bytes.Repeat([]byte("row\n"), 1000))
	header := bytes.Index(file, []byte("}\n")) + 2

	flipped := bytes.Clone(file)
	flipped[header+100] ^= 1
	cases := map[string][]byte{
		"truncated in the payload": file[:header+50],
		"truncated in the trailer": file[:len(file)-10],
		"no trailer":               file[:len(file)-trailerLen],
		"changed byte":             flipped,
		"bytes added":              append(bytes.Clone(file[:header]), append([]byte("extra"), file[header:]...)...),
	}
	for name, f := range cases {
		if _, _, err := readFile(bytes.NewReader(f)); !errors.Is(err, ErrDamaged) {
			t.Errorf("%s: err = %v, want ErrDamaged", name, err)
		}
	}
}

func TestFormatRefusesOtherFiles(t *testing.T) {
	for name, f := range map[string]string{
		"empty":          "",
		"age file":       "age-encryption.org/v1\n-> X25519 abc\n",
		"newer format":   "GUARDIAN-BACKUP 2\n{}\n",
		"bad manifest":   "GUARDIAN-BACKUP 1\nnot json\n",
		"bad encryption": "GUARDIAN-BACKUP 1\n{\"format\":1,\"encryption\":\"rot13\"}\n",
	} {
		if _, err := NewReader(strings.NewReader(f)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err := NewReader(strings.NewReader("GUARDIAN-BACKUP 2\n{}\n"))
	if err == nil || !strings.Contains(err.Error(), `format "2"`) {
		t.Errorf("a newer format should say so: %v", err)
	}
}

func TestRecipientListSkipsCommentsAndBlankLines(t *testing.T) {
	got := RecipientList("# Bitwarden: Guardian backup\nage1abc\n\n  age1def  \n")
	if strings.Join(got, ",") != "age1abc,age1def" {
		t.Errorf("got %q", got)
	}
}

func TestIssuerHost(t *testing.T) {
	if h := IssuerHost("https://auth.example.com"); h != "auth.example.com" {
		t.Errorf("host = %q", h)
	}
	if h := IssuerHost("http://localhost:3001"); h != "localhost:3001" {
		t.Errorf("host = %q", h)
	}
}
