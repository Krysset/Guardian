package web

// Notifications that are not about security (U19): each kind can come as an email each time, in a daily
// summary, or not at all, chosen per account under Account → Notifications. Security emails are not here:
// they always come.

import (
	"context"
	"log/slog"
	"time"

	"guardian/internal/httpx"
	"guardian/internal/mail"
	db "guardian/internal/store"
)

// NotificationKind is one kind of notification an account can choose how to get.
type NotificationKind struct {
	Key   string `json:"kind"`
	Panel string `json:"panel"` // owner (groups you own) or admin (Guardian administrators)
	Label string `json:"label"`
	Hint  string `json:"hint"`
}

const (
	KindGroupRequest        = "group_request"
	KindGroupRequestUnowned = "group_request_unowned"
)

// NotificationKinds are every kind, in the order the account area shows them.
var NotificationKinds = []NotificationKind{
	{KindGroupRequest, "owner", "Requests to join your groups", "When someone asks to join a group you own."},
	{KindGroupRequestUnowned, "admin", "Requests to join groups without owners", "Guardian administrators decide these."},
}

// NotificationKindsFor returns the kinds the account can receive: group owners get requests to join their
// groups, Guardian administrators those for groups without owners.
func NotificationKindsFor(accountID string) ([]NotificationKind, error) {
	owner, err := db.OwnsAnyGroup(accountID)
	if err != nil {
		return nil, err
	}
	admin, err := db.IsAdmin(accountID)
	if err != nil {
		return nil, err
	}
	var out []NotificationKind
	for _, k := range NotificationKinds {
		if (k.Panel == "owner" && owner) || (k.Panel == "admin" && admin) {
			out = append(out, k)
		}
	}
	return out, nil
}

// NotificationsURL is the account-area page with the choices, linked from every email that has them.
func NotificationsURL() string { return httpx.Issuer + "/account/notifications" }

// notify sends one notification as the account chose: compose builds the email for "now", and title and
// link are its line in the daily summary.
func notify(acct db.Account, kind, title, link string, compose func() mail.Message) {
	d, err := db.NotificationDelivery(acct.ID, kind)
	if err != nil {
		slog.Error("failed to read a notification setting", "error", err)
		d = db.DeliveryNow
	}
	switch d {
	case db.DeliveryOff:
	case db.DeliveryDaily:
		if err := db.QueueNotification(acct.ID, kind, title, link); err != nil {
			slog.Error("failed to keep a notification for the daily summary", "error", err)
			mail.Enqueue(compose()) // better twice than never
		}
	default:
		mail.Enqueue(compose())
	}
}

// SummaryInterval is how often the daily summaries are checked for.
var SummaryInterval = 10 * time.Minute

// StartSummaries sends the daily summaries until ctx ends. Every replica runs it; each summary goes out
// once (db.TakeSummary).
func StartSummaries(ctx context.Context) {
	go func() {
		t := time.NewTicker(SummaryInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				SendDueSummaries(time.Now())
			}
		}
	}()
}

// summarySlot is the latest time at or before now when the account's summary was due: today at its hour
// in its time zone, or yesterday's if that is still to come.
func summarySlot(now time.Time, hour int, zone string) time.Time {
	loc, err := time.LoadLocation(zone)
	if zone == "" || err != nil {
		loc = time.UTC
	}
	local := now.In(loc)
	slot := time.Date(local.Year(), local.Month(), local.Day(), hour, 0, 0, 0, loc)
	if slot.After(local) {
		slot = time.Date(local.Year(), local.Month(), local.Day()-1, hour, 0, 0, 0, loc)
	}
	return slot
}

// SendDueSummaries sends every summary that is due at now: one whose notifications waited since before its
// latest slot, and that has not gone out since that slot. Notifications that came after the slot wait for
// the next one.
func SendDueSummaries(now time.Time) {
	candidates, err := db.SummaryCandidates()
	if err != nil {
		slog.Error("failed to find daily summaries to send", "error", err)
		return
	}
	for _, c := range candidates {
		slot := summarySlot(now, c.Hour, c.Zoneinfo)
		if !c.OldestPending.Before(slot) {
			continue
		}
		items, err := db.TakeSummary(c.AccountID, func(last *time.Time) bool { return last == nil || last.Before(slot) })
		if err != nil {
			slog.Error("failed to take a daily summary", "error", err)
			continue
		}
		if len(items) == 0 {
			continue
		}
		lines := make([]mail.Item, len(items))
		for i, n := range items {
			lines[i] = mail.Item{Title: n.Title, When: mail.When(n.CreatedAt, c.Zoneinfo), URL: n.Link}
		}
		mail.Enqueue(mail.DailySummary(c.Email, lines, NotificationsURL()))
	}
}
