package auth

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashPasswordFormatAndVerify(t *testing.T) {
	hash, err := HashPassword("s3cret-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=2,p=2$") {
		t.Fatalf("unexpected PHC prefix: %s", hash)
	}
	if !VerifyPassword("s3cret-passphrase", hash) {
		t.Error("correct password rejected")
	}
	for _, wrong := range []string{"", "s3cret-passphrasE", "s3cret-passphrase ", "other"} {
		if VerifyPassword(wrong, hash) {
			t.Errorf("wrong password %q accepted", wrong)
		}
	}
}

func TestHashPasswordIsSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("two hashes of the same password are identical: salt is not random")
	}
	if !VerifyPassword("same", a) || !VerifyPassword("same", b) {
		t.Fatal("both salted hashes must verify")
	}
}

func TestVerifyPasswordRejectsMalformedHashes(t *testing.T) {
	valid, _ := HashPassword("pw")
	parts := strings.Split(valid, "$")
	withParams := func(p string) string {
		cp := append([]string{}, parts...)
		cp[3] = p
		return strings.Join(cp, "$")
	}
	cases := map[string]string{
		"empty":                "",
		"plaintext":            "pw",
		"bcrypt":               "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
		"truncated":            "$argon2id$v=19$m=65536,t=2,p=2$",
		"wrong algorithm":      strings.Replace(valid, "argon2id", "argon2i", 1),
		"wrong version":        strings.Replace(valid, "v=19", "v=16", 1),
		"memory bomb":          withParams("m=4194304,t=2,p=2"),
		"iteration bomb":       withParams("m=65536,t=1000,p=2"),
		"zero threads":         withParams("m=65536,t=2,p=0"),
		"zero memory":          withParams("m=0,t=2,p=2"),
		"garbage params":       withParams("nonsense"),
		"bad salt base64":      strings.Join([]string{"", "argon2id", "v=19", "m=65536,t=2,p=2", "!!!", parts[5]}, "$"),
		"bad key base64":       strings.Join([]string{"", "argon2id", "v=19", "m=65536,t=2,p=2", parts[4], "!!!"}, "$"),
		"key too short":        strings.Join([]string{"", "argon2id", "v=19", "m=65536,t=2,p=2", parts[4], "AAAA"}, "$"),
		"extra fields":         valid + "$extra",
	}
	for name, h := range cases {
		if VerifyPassword("pw", h) {
			t.Errorf("%s: accepted a malformed hash", name)
		}
	}
}

// Parameters are read from the stored hash, so the cost can be raised later without breaking old hashes.
func TestVerifyPasswordHonoursStoredParameters(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte("legacy"), salt, 1, 8*1024, 1, 32)
	legacy := fmt.Sprintf("$argon2id$v=%d$m=8192,t=1,p=1$%s$%s", argon2.Version,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	if !VerifyPassword("legacy", legacy) {
		t.Error("hash made with weaker parameters must still verify")
	}
	if VerifyPassword("other", legacy) {
		t.Error("wrong password accepted for legacy hash")
	}
}

func TestDummyVerifyNeverSucceedsAndReleasesSlots(t *testing.T) {
	DummyVerify("anything")
	if len(hashSlots) != 0 {
		t.Fatalf("%d hashing slots still held", len(hashSlots))
	}
	if cap(hashSlots) != maxConcurrentHashes {
		t.Fatalf("slot capacity = %d, want %d", cap(hashSlots), maxConcurrentHashes)
	}
}

// More concurrent verifications than slots must all finish (no deadlock) and give correct answers.
func TestConcurrentVerificationsAreBoundedButComplete(t *testing.T) {
	hash, _ := HashPassword("pw")
	var wg sync.WaitGroup
	results := make([]bool, 3*maxConcurrentHashes)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pw := "pw"
			if i%2 == 1 {
				pw = "wrong"
			}
			results[i] = VerifyPassword(pw, hash) == (pw == "pw")
		}(i)
	}
	wg.Wait()
	for i, ok := range results {
		if !ok {
			t.Errorf("verification %d returned the wrong answer", i)
		}
	}
	if len(hashSlots) != 0 {
		t.Fatalf("%d hashing slots leaked", len(hashSlots))
	}
}

func TestRandomTokenAndHashToken(t *testing.T) {
	seen := map[string]bool{}
	urlSafe := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	for i := 0; i < 200; i++ {
		tok, err := RandomToken(32)
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != 43 || !urlSafe.MatchString(tok) {
			t.Fatalf("token %q is not 43 url-safe characters", tok)
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
	h := HashToken("abc")
	if h != HashToken("abc") || h == HashToken("abd") {
		t.Fatal("HashToken must be deterministic and input-sensitive")
	}
	if h != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("HashToken is not hex SHA-256: %s", h)
	}
}

func TestNewUUIDIsV4(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := NewUUID()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(id) {
			t.Fatalf("not a v4 UUID: %s", id)
		}
		if seen[id] {
			t.Fatal("duplicate uuid")
		}
		seen[id] = true
	}
}
