package e2e

import (
	"strings"
	"testing"
	"time"

	"guardian/internal/testutil"
	"guardian/internal/web"
)

// Notifications that are not about security: each account chooses per kind between an email right away,
// the daily summary, and nothing. Only the kinds an account can receive are offered.
//
// Covers: U21
func TestE2ENotificationsComeAsEachAccountChose(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "root")
	setEmail(t, "root", "root@hyrule.example")
	owner := testutil.CreateAccount(t, "owner")
	setEmail(t, "owner", "owner@hyrule.example")
	testutil.CreateAccount(t, "alice")
	testutil.CreateAccount(t, "bob")
	stewards := testutil.Group(t, "stewards", "")
	testutil.AddMember(t, stewards, owner.ID)
	wiki := testutil.Group(t, "wiki-users", stewards)
	orphans := testutil.Group(t, "orphans", "")
	testutil.Exec(t, `UPDATE user_group SET requestable = TRUE WHERE id IN ($1, $2)`, wiki, orphans)

	kinds := func(v map[string]any) []string {
		var out []string
		for _, s := range v["settings"].([]any) {
			m := s.(map[string]any)
			out = append(out, str(m["kind"])+"="+str(m["delivery"]))
		}
		return out
	}

	// Someone who owns nothing has nothing to choose, and no address to send to.
	alice := newBrowser(t)
	alice.mustLogin("alice")
	if v := alice.call("GET", "/api/v1/me/notifications", nil, 200); len(kinds(v)) != 0 || v["email"] != "" {
		t.Errorf("a plain account's notifications: %v", v)
	}
	alice.call("PUT", "/api/v1/me/notifications", map[string]any{"settings": map[string]any{"group_request": "off"}}, 400)

	// A group owner chooses for requests to join their groups; an administrator for groups without owners.
	ob := newBrowser(t)
	ob.mustLogin("owner")
	v := ob.call("GET", "/api/v1/me/notifications", nil, 200)
	if got := strings.Join(kinds(v), ","); got != "group_request=now" || v["email"] != "owner@hyrule.example" || v["summary_hour"] != float64(8) {
		t.Fatalf("the owner's notifications: %v", v)
	}
	ob.call("PUT", "/api/v1/me/notifications", map[string]any{"settings": map[string]any{"group_request_unowned": "off"}}, 400)
	ob.call("PUT", "/api/v1/me/notifications", map[string]any{"settings": map[string]any{"group_request": "sometimes"}}, 400)
	ob.call("PUT", "/api/v1/me/notifications", map[string]any{"summary_hour": 24}, 400)
	root := newBrowser(t)
	root.mustLogin("root")
	if got := strings.Join(kinds(root.call("GET", "/api/v1/me/notifications", nil, 200)), ","); got != "group_request_unowned=now" {
		t.Errorf("an administrator's notifications: %s", got)
	}

	// Daily: no email now; the request waits for the summary at the chosen hour, in UTC without a time zone.
	v = ob.call("PUT", "/api/v1/me/notifications", map[string]any{"settings": map[string]any{"group_request": "daily"}, "summary_hour": 9}, 200)
	if got := strings.Join(kinds(v), ","); got != "group_request=daily" || v["summary_hour"] != float64(9) {
		t.Fatalf("after the change: %v", v)
	}
	alice.call("POST", "/api/v1/me/group-requests", map[string]any{"group_id": wiki, "message": "I write docs"}, 201)
	if _, ok := mailbox.WaitFor("owner@hyrule.example", "alice asks to join"); ok {
		t.Error("an owner who chose the daily summary was emailed right away")
	}
	if n := testutil.Count(t, `SELECT count(*) FROM notification_pending WHERE account_id = $1`, owner.ID); n != 1 {
		t.Fatalf("%d notifications wait for the summary, want 1", n)
	}

	now := time.Now().UTC()
	nineToday := time.Date(now.Year(), now.Month(), now.Day(), 9, 0, 0, 0, time.UTC)
	web.SendDueSummaries(now.Add(-48 * time.Hour)) // before the request: nothing is due
	if n := testutil.Count(t, `SELECT count(*) FROM notification_pending`); n != 1 {
		t.Fatal("a summary went out before the request it holds")
	}
	slot := nineToday // the first 09:00 after the request
	if !slot.After(now) {
		slot = slot.Add(24 * time.Hour)
	}
	next := slot.Add(30 * time.Minute)
	web.SendDueSummaries(next)
	m, ok := mailbox.WaitFor("owner@hyrule.example", "Your daily summary: 1 thing")
	if !ok || !strings.Contains(m.Text, "alice asks to join Group wiki-users") || !strings.Contains(m.Text, "/account/groups/"+wiki) ||
		!strings.Contains(m.Text, "/account/notifications") {
		t.Fatalf("the summary: %v %s", ok, m.Text)
	}
	before := len(mailbox.Messages())
	web.SendDueSummaries(next.Add(time.Hour)) // the same day: nothing more
	if len(mailbox.Messages()) != before || testutil.Count(t, `SELECT count(*) FROM notification_pending`) != 0 {
		t.Error("a summary went out twice, or kept its notifications")
	}

	// Off: nothing at all. An administrator who did not choose gets requests for groups without owners
	// right away.
	ob.call("PUT", "/api/v1/me/notifications", map[string]any{"settings": map[string]any{"group_request": "off"}}, 200)
	bob := newBrowser(t)
	bob.mustLogin("bob")
	bob.call("POST", "/api/v1/me/group-requests", map[string]any{"group_id": wiki}, 201)
	bob.call("POST", "/api/v1/me/group-requests", map[string]any{"group_id": orphans}, 201)
	if m, ok := mailbox.WaitFor("root@hyrule.example", "bob asks to join Group orphans"); !ok || !strings.Contains(m.Text, "/account/notifications") {
		t.Errorf("the administrator's email: %v %s", ok, m.Text)
	}
	if _, ok := mailbox.WaitFor("owner@hyrule.example", "bob asks to join"); ok {
		t.Error("an owner who turned requests off was emailed")
	}
	if n := testutil.Count(t, `SELECT count(*) FROM notification_pending`); n != 0 {
		t.Error("a notification turned off was kept for a summary")
	}
}
