package web

import (
	"testing"
	"time"
)

// Covers: U21
func TestSummarySlotIsTheLatestChosenHourInTheAccountsZone(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, c := range []struct {
		now, zone string
		hour      int
		want      string
	}{
		{"2026-11-21T09:30:00Z", "", 9, "2026-11-21T09:00:00Z"},
		{"2026-11-21T08:59:00Z", "", 9, "2026-11-20T09:00:00Z"},
		{"2026-11-21T07:30:00Z", "Europe/Stockholm", 8, "2026-11-21T07:00:00Z"}, // 08:00 in Stockholm (UTC+1)
		{"2026-11-21T06:30:00Z", "Europe/Stockholm", 8, "2026-11-20T07:00:00Z"},
		{"2026-03-29T07:30:00Z", "Europe/Stockholm", 8, "2026-03-29T06:00:00Z"}, // summer time began that night
		{"2026-11-21T09:30:00Z", "Nowhere/Invalid", 9, "2026-11-21T09:00:00Z"},
	} {
		if got := summarySlot(at(c.now), c.hour, c.zone); !got.Equal(at(c.want)) {
			t.Errorf("summarySlot(%s, %d, %q) = %s, want %s", c.now, c.hour, c.zone, got.UTC().Format(time.RFC3339), c.want)
		}
	}
}
