package store

// The admin area's start page (AD13) shows figures only: nothing in Overview identifies a person.

// RefusedKeyPrefix starts the rate_limit keys that count refused requests per endpoint and hour
// (httpx.CountRefused). They are statistics, not limits: nothing checks them.
const RefusedKeyPrefix = "refused:"

// Overview is the admin area's aggregated figures.
type Overview struct {
	Accounts struct {
		Active          int `json:"active"`
		Disabled        int `json:"disabled"`
		MustChange      int `json:"must_change_password"`
		WaitingForErase int `json:"waiting_for_erasure"`
	} `json:"accounts"`
	Groups int `json:"groups"`
	Apps   struct {
		Enabled  int `json:"enabled"`
		Disabled int `json:"disabled"`
	} `json:"apps"`
	// LastDay counts events of the last 24 hours.
	LastDay struct {
		SignIns        int `json:"sign_ins"`
		FailedSignIns  int `json:"failed_sign_ins"`
		RateLimited    int `json:"rate_limited"`
		HoneypotCaught int `json:"honeypot"`
	} `json:"last_day"`
	Admins struct {
		Total      int `json:"total"`
		WithTOTP   int `json:"with_two_factor"`
		Permanent  int `json:"permanent"` // whose membership does not expire: the ones the last-administrator rule counts
		LastSignIn int `json:"signed_in_last_day"`
	} `json:"admins"`
}

// GetOverview computes the figures in one round trip.
func GetOverview() (Overview, error) {
	var o Overview
	err := GetDatabaseConnection().QueryRow(`SELECT
		(SELECT count(*) FROM account WHERE deleted_at IS NULL AND status = 'active'),
		(SELECT count(*) FROM account WHERE deleted_at IS NULL AND status = 'disabled'),
		(SELECT count(*) FROM account WHERE deleted_at IS NULL AND status = 'active' AND must_change_password),
		(SELECT count(*) FROM account WHERE deleted_at IS NOT NULL),
		(SELECT count(*) FROM user_group),
		(SELECT count(*) FROM app WHERE enabled),
		(SELECT count(*) FROM app WHERE NOT enabled),
		(SELECT count(*) FROM audit_log WHERE event_type = 'login.success' AND occurred_at > now() - interval '1 day'),
		(SELECT count(*) FROM audit_log WHERE event_type IN ('login.failure', 'mfa.failure') AND occurred_at > now() - interval '1 day'),
		(SELECT COALESCE(sum(hits), 0) FROM rate_limit
		  WHERE key LIKE $1 AND key <> $2 AND window_start > now() - interval '1 day'),
		(SELECT COALESCE(sum(hits), 0) FROM rate_limit WHERE key = $2 AND window_start > now() - interval '1 day'),
		(SELECT count(DISTINCT m.account_id) FROM group_member m JOIN user_group g ON g.id = m.group_id
		   JOIN account a ON a.id = m.account_id
		  WHERE g.key = $3 AND `+activeMember+` AND a.status = 'active' AND a.deleted_at IS NULL),
		(SELECT count(DISTINCT m.account_id) FROM group_member m JOIN user_group g ON g.id = m.group_id
		   JOIN account a ON a.id = m.account_id JOIN account_mfa f ON f.account_id = a.id AND f.type = 'totp'
		  WHERE g.key = $3 AND `+activeMember+` AND a.status = 'active' AND a.deleted_at IS NULL),
		(SELECT count(DISTINCT m.account_id) FROM group_member m JOIN user_group g ON g.id = m.group_id
		   JOIN account a ON a.id = m.account_id
		  WHERE g.key = $3 AND m.expires_at IS NULL AND a.status = 'active' AND a.deleted_at IS NULL),
		(SELECT count(DISTINCT m.account_id) FROM group_member m JOIN user_group g ON g.id = m.group_id
		   JOIN account a ON a.id = m.account_id
		  WHERE g.key = $3 AND `+activeMember+` AND a.last_login_at > now() - interval '1 day')`,
		RefusedKeyPrefix+"%", RefusedKeyPrefix+"honeypot", AdminGroupKey).Scan(
		&o.Accounts.Active, &o.Accounts.Disabled, &o.Accounts.MustChange, &o.Accounts.WaitingForErase,
		&o.Groups, &o.Apps.Enabled, &o.Apps.Disabled,
		&o.LastDay.SignIns, &o.LastDay.FailedSignIns, &o.LastDay.RateLimited, &o.LastDay.HoneypotCaught,
		&o.Admins.Total, &o.Admins.WithTOTP, &o.Admins.Permanent, &o.Admins.LastSignIn)
	return o, err
}
