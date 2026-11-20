package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	db "guardian/internal/store"
)

// Key maintenance runs every minute on every replica: it reloads the keyring file, moves the signing keys
// along their schedule, reloads the signing keys, and re-encrypts values still under an older keyring key.

// KeyMaintenanceInterval is how often RunKeyMaintenance runs.
const KeyMaintenanceInterval = time.Minute

var keyringValues = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "guardian", Name: "keyring_values",
	Help: "Encrypted values in the database per keyring key. A key may be removed from the keyring once it has none.",
}, []string{"key_id"})

// DefaultSchedule is the signing-key schedule: 90 days per key, published an hour before it signs, and
// five minutes of clock skew after the longest token lifetime before a retiring key is unpublished.
var DefaultSchedule = db.KeySchedule{Lifetime: 90 * 24 * time.Hour, Pending: time.Hour, Skew: 5 * time.Minute}

// ValuesPerKey counts the stored values under each keyring key id.
func ValuesPerKey() (map[string]int, error) {
	values, err := db.EncryptedValues()
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, v := range values {
		out[KeyIDOf(v.Value)]++
	}
	return out, nil
}

// CheckKeyring returns an error if the keyring lacks a key that stored values need. Guardian refuses to
// start with such a keyring, and a reload keeps the previous one.
func CheckKeyring(r *Keyring) error {
	needed, err := ValuesPerKey()
	if err != nil {
		return err
	}
	var missing []string
	for id := range needed {
		if id == "" {
			missing = append(missing, "(values in an older format: recreate the database)")
		} else if !r.Has(id) {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("the keyring lacks key(s) %s, which stored values are encrypted with", strings.Join(missing, ", "))
	}
	return nil
}

// LoadKeyringFile reads a keyring file.
func LoadKeyringFile(path string) (*Keyring, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := ParseKeyring(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// Reencrypt rewrites every stored value that is not under the primary key, and returns how many it moved.
func Reencrypt() (int, error) {
	r := CurrentKeyring()
	if r == nil {
		return 0, errors.New("the encryption keyring is not set")
	}
	values, err := db.EncryptedValues()
	if err != nil {
		return 0, err
	}
	moved := 0
	for _, v := range values {
		if KeyIDOf(v.Value) == r.Primary().ID {
			continue
		}
		aad := AAD(v.Table, v.Column, v.Row)
		plain, err := Decrypt(v.Value, aad)
		if err != nil {
			return moved, fmt.Errorf("%s of %s: %w", v.Table, v.Row, err)
		}
		next, err := Encrypt(plain, aad)
		if err != nil {
			return moved, err
		}
		if ok, err := db.ReplaceEncryptedValue(v, next); err != nil {
			return moved, err
		} else if ok {
			moved++
		}
	}
	return moved, nil
}

// MaintainKeys runs one round of key maintenance. keyringFile is "" when the keyring came from the
// environment (it cannot change then).
func MaintainKeys(keys *Keys, schedule db.KeySchedule, keyringFile string) {
	if keyringFile != "" {
		if r, err := LoadKeyringFile(keyringFile); err != nil {
			slog.Error("reloading the keyring failed; keeping the previous one", "error", err)
		} else if err := CheckKeyring(r); err != nil {
			slog.Error("the new keyring is refused; keeping the previous one", "error", err)
		} else if old := CurrentKeyring(); old == nil || !sameKeyring(old, r) {
			SetKeyring(r)
			slog.Info("loaded a changed keyring", "primary", r.Primary().ID, "keys", len(r.keys))
		}
	}
	steps, err := db.AdvanceSigningKeys(schedule, NewSigningKey)
	if err != nil {
		slog.Error("the signing-key schedule failed", "error", err)
	}
	for _, s := range steps {
		slog.Info("signing key "+strings.TrimPrefix(s.Event, "signing_key."), "kid", s.KID)
		db.Audit(s.Event, "", "", "", map[string]any{"kid": s.KID, "by": "schedule"})
	}
	if err := keys.Reload(); err != nil {
		slog.Error("reloading the signing keys failed; keeping the previous ones", "error", err)
	}
	if n, err := Reencrypt(); err != nil {
		slog.Error("re-encrypting with the keyring's primary key failed", "error", err)
	} else if n > 0 {
		slog.Info("re-encrypted values with the keyring's primary key", "count", n, "key_id", CurrentKeyring().Primary().ID)
	}
	updateKeyringMetric()
}

func sameKeyring(a, b *Keyring) bool {
	if len(a.keys) != len(b.keys) {
		return false
	}
	for i := range a.keys {
		if a.keys[i].ID != b.keys[i].ID || a.keys[i].Fingerprint() != b.keys[i].Fingerprint() {
			return false
		}
	}
	return true
}

func updateKeyringMetric() {
	counts, err := ValuesPerKey()
	if err != nil {
		return
	}
	keyringValues.Reset()
	if r := CurrentKeyring(); r != nil {
		for _, k := range r.keys {
			keyringValues.WithLabelValues(k.ID).Set(0)
		}
	}
	for id, n := range counts {
		keyringValues.WithLabelValues(id).Set(float64(n))
	}
}

// RunKeyMaintenance runs MaintainKeys every KeyMaintenanceInterval until ctx ends.
func RunKeyMaintenance(ctx context.Context, keys *Keys, schedule db.KeySchedule, keyringFile string) {
	go func() {
		t := time.NewTicker(KeyMaintenanceInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				MaintainKeys(keys, schedule, keyringFile)
			}
		}
	}()
}
