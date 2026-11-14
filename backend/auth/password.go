package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (OWASP-recommended range). Stored in the hash, so they can be raised later.
const (
	argonIterations = 2
	argonMemoryKiB  = 64 * 1024
	argonThreads    = 2
	argonKeyLen     = 32
	argonSaltLen    = 16
)

// maxConcurrentHashes bounds simultaneous argon2 runs: each needs argonMemoryKiB of RAM, so an
// unbounded login burst would exceed a Kubernetes memory limit and get the pod OOM-killed.
// Peak hashing memory = maxConcurrentHashes x 64 MiB; size the pod's memory limit accordingly.
const maxConcurrentHashes = 4

var hashSlots = make(chan struct{}, maxConcurrentHashes)

func deriveKey(password string, salt []byte, iterations, memory uint32, threads uint8, keyLen uint32) []byte {
	hashSlots <- struct{}{}
	defer func() { <-hashSlots }()
	return argon2.IDKey([]byte(password), salt, iterations, memory, threads, keyLen)
}

// dummyHash lets us spend the same time on unknown usernames as on wrong passwords.
var dummyHash, _ = HashPassword("guardian-dummy-password")

// HashPassword returns a PHC-format argon2id hash.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := deriveKey(password, salt, argonIterations, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonIterations, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a hash made by HashPassword.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	// Refuse absurd parameters so a corrupted row can't be used to exhaust memory/CPU.
	if memory == 0 || memory > 256*1024 || iterations == 0 || iterations > 10 || threads == 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 {
		return false
	}
	got := deriveKey(password, salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// DummyVerify burns the same CPU as a real verification (used for unknown users).
func DummyVerify(password string) {
	VerifyPassword(password, dummyHash)
}

// RandomToken returns n random bytes, base64url encoded (no padding).
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken is the storage form of any high-entropy secret (session ids, codes,
// refresh tokens, client secrets). A fast hash is fine because the input is random.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewUUID returns a random (v4) UUID.
func NewUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
