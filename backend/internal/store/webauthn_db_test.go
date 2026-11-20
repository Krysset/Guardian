package store_test

import (
	"errors"
	"sync"
	"testing"

	db "guardian/internal/store"
	"guardian/internal/testutil"
)

func TestSecurityKeysAreUniqueAndTheLastFactorIsKept(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "sidon")
	other := testutil.CreateAccount(t, "yona")
	codes := []string{"h1", "h2"}
	a, err := db.AddSecurityKey(acct.ID, "One", []byte{1}, []byte(`{"flags":{"backupEligible":true}}`), 0, codes)
	if err != nil || !a.Passkey || a.Name != "One" {
		t.Fatalf("first key: %+v (%v)", a, err)
	}
	if _, err := db.AddSecurityKey(other.ID, "Copy", []byte{1}, []byte(`{}`), 0, nil); !errors.Is(err, db.ErrCredentialInUse) {
		t.Errorf("a credential registered twice: %v", err)
	}
	b, err := db.AddSecurityKey(acct.ID, "Two", []byte{2}, []byte(`{}`), 0, nil)
	if err != nil || b.Passkey {
		t.Fatalf("second key: %+v (%v)", b, err)
	}
	if owner, err := db.AccountForCredential([]byte{2}); err != nil || owner != acct.ID {
		t.Errorf("credential 2 belongs to %q (%v)", owner, err)
	}

	// Two removals at once on an account that must keep a method: exactly one succeeds.
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i, id := range []string{a.ID, b.ID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, results[i] = db.RemoveFactor(acct.ID, id, true)
		}()
	}
	wg.Wait()
	if (results[0] == nil) == (results[1] == nil) || !(errors.Is(results[0], db.ErrLastFactor) || errors.Is(results[1], db.ErrLastFactor)) {
		t.Fatalf("concurrent removals: %v", results)
	}
	if st, _ := db.GetMFAStatus(acct.ID); len(st.SecurityKeys) != 1 || st.RecoveryCodesLeft != 2 {
		t.Errorf("after one removal: %+v", st)
	}

	// Without the requirement the last one may go, and the recovery codes go with it.
	left, _ := db.GetMFAStatus(acct.ID)
	if _, n, err := db.RemoveFactor(acct.ID, left.SecurityKeys[0].ID, false); err != nil || n != 0 {
		t.Fatalf("removing the last key: %d left (%v)", n, err)
	}
	if st, _ := db.GetMFAStatus(acct.ID); st.Any() || st.RecoveryCodesLeft != 0 {
		t.Errorf("after removing the last method: %+v", st)
	}
	if _, _, err := db.RemoveFactor(acct.ID, "totp", false); !errors.Is(err, db.ErrNoTOTP) {
		t.Errorf("removing a missing app: %v", err)
	}
	if err := db.ReplaceRecoveryCodes(acct.ID, codes); !errors.Is(err, db.ErrNoSecondFactor) {
		t.Errorf("recovery codes without a method: %v", err)
	}
}
