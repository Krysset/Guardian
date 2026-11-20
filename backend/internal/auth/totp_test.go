package auth

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, with the 20-byte key "12345678901234567890" (the 8-digit values cut to 6).
func TestTOTPMatchesTheRFC(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471",
		1234567890: "005924", 2000000000: "279037", 20000000000: "353130"} {
		got, err := TOTPCode(secret, TOTPStep(time.Unix(unix, 0)))
		if err != nil || got != want {
			t.Errorf("T=%d: %s (%v), want %s", unix, got, err, want)
		}
	}
}

func TestVerifyTOTPAllowsDriftAndRefusesReplays(t *testing.T) {
	secret, _ := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	step := TOTPStep(now)
	code := func(s int64) string { c, _ := TOTPCode(secret, s); return c }
	for _, s := range []int64{step - 1, step, step + 1} {
		if got, ok := VerifyTOTP(secret, code(s)[:3]+" "+code(s)[3:], now, 0); !ok || got != s {
			t.Errorf("step %+d refused", s-step)
		}
	}
	for _, s := range []int64{step - 2, step + 2} {
		if _, ok := VerifyTOTP(secret, code(s), now, 0); ok {
			t.Errorf("step %+d accepted", s-step)
		}
	}
	if _, ok := VerifyTOTP(secret, code(step), now, step); ok {
		t.Error("a used code was accepted again")
	}
	if _, ok := VerifyTOTP(secret, code(step+1), now, step); !ok {
		t.Error("the next code was refused after a used one")
	}
	if _, ok := VerifyTOTP(secret, "12345", now, 0); ok {
		t.Error("a short code was accepted")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := NewRecoveryCodes()
	if err != nil || len(codes) != 10 {
		t.Fatal(codes, err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 9 || c[4] != '-' || strings.ContainsAny(c, "ilou") || seen[c] {
			t.Errorf("bad or repeated code %q", c)
		}
		seen[c] = true
	}
	if HashRecoveryCode("a", "AB1C-0DEF") != HashRecoveryCode("a", " abic odef ") {
		t.Error("typing variants must match")
	}
	if HashRecoveryCode("a", codes[0]) == HashRecoveryCode("b", codes[0]) {
		t.Error("the account id must be part of the hash")
	}
	uri := OTPAuthURI("Hyrule Guardian", "link", "JBSWY3DPEHPK3PXP")
	if !strings.HasPrefix(uri, "otpauth://totp/Hyrule%20Guardian:link?") || !strings.Contains(uri, "issuer=Hyrule+Guardian") {
		t.Errorf("uri = %s", uri)
	}
	if GroupSecret("JBSWY3DPEHPK3PXPAB") != "JBSW Y3DP EHPK 3PXP AB" {
		t.Error(GroupSecret("JBSWY3DPEHPK3PXPAB"))
	}
}
