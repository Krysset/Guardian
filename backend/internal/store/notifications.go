package store

import (
	"database/sql"
	"slices"
	"time"
)

// Delivery is how an account gets one kind of notification.
type Delivery string

const (
	DeliveryOff   Delivery = "off"
	DeliveryNow   Delivery = "now"   // an email each time
	DeliveryDaily Delivery = "daily" // in the daily summary
)

// DefaultSummaryHour is when the daily summary comes for an account that has not chosen.
const DefaultSummaryHour = 8

// NotificationDelivery returns how the account gets the kind; DeliveryNow when it has not chosen.
func NotificationDelivery(accountID, kind string) (Delivery, error) {
	var d Delivery
	err := GetDatabaseConnection().QueryRow(
		`SELECT delivery FROM notification_setting WHERE account_id = $1 AND kind = $2`, accountID, kind).Scan(&d)
	if err == sql.ErrNoRows {
		return DeliveryNow, nil
	}
	return d, err
}

// NotificationSettings returns the account's choices, by kind, and its summary hour.
func NotificationSettings(accountID string) (map[string]Delivery, int, error) {
	rows, err := GetDatabaseConnection().Query(`SELECT kind, delivery FROM notification_setting WHERE account_id = $1`, accountID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := map[string]Delivery{}
	for rows.Next() {
		var k string
		var d Delivery
		if err := rows.Scan(&k, &d); err != nil {
			return nil, 0, err
		}
		out[k] = d
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	hour := DefaultSummaryHour
	err = GetDatabaseConnection().QueryRow(`SELECT summary_hour FROM notification_schedule WHERE account_id = $1`, accountID).Scan(&hour)
	if err != nil && err != sql.ErrNoRows {
		return nil, 0, err
	}
	return out, hour, nil
}

// SetNotificationSettings saves the given choices (others stay as they are) and, when hour is not nil, the
// summary hour, in one transaction.
func SetNotificationSettings(accountID string, settings map[string]Delivery, hour *int) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for kind, d := range settings {
		if _, err := tx.Exec(`INSERT INTO notification_setting (account_id, kind, delivery) VALUES ($1, $2, $3)
			ON CONFLICT (account_id, kind) DO UPDATE SET delivery = EXCLUDED.delivery`, accountID, kind, d); err != nil {
			return err
		}
		if d != DeliveryDaily {
			// Waiting notifications of a kind no longer summarised are dropped: "off" means no more of them,
			// and "now" only applies from now on.
			if _, err := tx.Exec(`DELETE FROM notification_pending WHERE account_id = $1 AND kind = $2`, accountID, kind); err != nil {
				return err
			}
		}
	}
	if hour != nil {
		if _, err := tx.Exec(`INSERT INTO notification_schedule (account_id, summary_hour) VALUES ($1, $2)
			ON CONFLICT (account_id) DO UPDATE SET summary_hour = EXCLUDED.summary_hour`, accountID, *hour); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueueNotification keeps a notification for the account's next daily summary.
func QueueNotification(accountID, kind, title, link string) error {
	_, err := GetDatabaseConnection().Exec(
		`INSERT INTO notification_pending (account_id, kind, title, link) VALUES ($1, $2, $3, $4)`, accountID, kind, title, link)
	return err
}

// PendingNotification is one line of a daily summary.
type PendingNotification struct {
	Kind, Title, Link string
	CreatedAt         time.Time
}

// SummaryCandidate is an account with notifications waiting.
type SummaryCandidate struct {
	AccountID, Email, Zoneinfo string
	Hour                       int
	OldestPending              time.Time
}

// SummaryCandidates returns the accounts with notifications waiting and a confirmed address.
func SummaryCandidates() ([]SummaryCandidate, error) {
	rows, err := GetDatabaseConnection().Query(`SELECT a.id, a.email, COALESCE(a.zoneinfo, ''),
			COALESCE(s.summary_hour, $1),
			(SELECT min(p.created_at) FROM notification_pending p WHERE p.account_id = a.id)
		FROM account a LEFT JOIN notification_schedule s ON s.account_id = a.id
		WHERE a.status = 'active' AND a.deleted_at IS NULL AND a.email IS NOT NULL AND a.email_verified_at IS NOT NULL
		  AND EXISTS (SELECT 1 FROM notification_pending p WHERE p.account_id = a.id)`, DefaultSummaryHour)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SummaryCandidate
	for rows.Next() {
		var c SummaryCandidate
		if err := rows.Scan(&c.AccountID, &c.Email, &c.Zoneinfo, &c.Hour, &c.OldestPending); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// TakeSummary removes the account's waiting notifications and records that its summary went out, in one
// transaction, and returns them, oldest first. When several replicas run the schedule, only one gets them.
// due decides, from the last summary's time (nil if none), whether the summary is due; it is called with
// the account's schedule row locked.
func TakeSummary(accountID string, due func(last *time.Time) bool) ([]PendingNotification, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO notification_schedule (account_id) VALUES ($1) ON CONFLICT DO NOTHING`, accountID); err != nil {
		return nil, err
	}
	var last sql.NullTime
	if err := tx.QueryRow(`SELECT last_summary_at FROM notification_schedule WHERE account_id = $1 FOR UPDATE`, accountID).Scan(&last); err != nil {
		return nil, err
	}
	var lastp *time.Time
	if last.Valid {
		lastp = &last.Time
	}
	if !due(lastp) {
		return nil, nil
	}
	rows, err := tx.Query(`DELETE FROM notification_pending WHERE account_id = $1 RETURNING kind, title, link, created_at`, accountID)
	if err != nil {
		return nil, err
	}
	var out []PendingNotification
	for rows.Next() {
		var n PendingNotification
		if err := rows.Scan(&n.Kind, &n.Title, &n.Link, &n.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	if _, err := tx.Exec(`UPDATE notification_schedule SET last_summary_at = now() WHERE account_id = $1`, accountID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b PendingNotification) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

// OwnsAnyGroup reports whether the account is an active member of some group's owner group (other than
// the built-in administrators' group, whose groups are the administrators' own notification).
func OwnsAnyGroup(accountID string) (bool, error) {
	var ok bool
	err := GetDatabaseConnection().QueryRow(`SELECT EXISTS (SELECT 1 FROM user_group g
		JOIN group_member m ON m.group_id = g.owner_group_id AND m.account_id = $1
		JOIN user_group o ON o.id = g.owner_group_id
		WHERE o.key <> $2 AND `+activeMember+`)`, accountID, AdminGroupKey).Scan(&ok)
	return ok, err
}
