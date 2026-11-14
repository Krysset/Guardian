package database

import "time"

// Fixed-window rate limiting in Postgres (UNLOGGED table, see schema.sql). Accurate across all replicas,
// no extra infrastructure. Intended for low-volume, expensive endpoints (login, sign-up), not per-request limits.

const windowStartSQL = `to_timestamp(floor(extract(epoch FROM now()) / $2) * $2)`

// RateLimitHit counts one event for key and returns the number of events in the current window.
func RateLimitHit(key string, window time.Duration) (int, error) {
	var hits int
	err := GetDatabaseConnection().QueryRow(
		`INSERT INTO rate_limit (key, window_start, hits) VALUES ($1, `+windowStartSQL+`, 1)
		 ON CONFLICT (key, window_start) DO UPDATE SET hits = rate_limit.hits + 1
		 RETURNING hits`, key, window.Seconds()).Scan(&hits)
	return hits, err
}

// RateLimitCount returns the events counted so far in the current window without adding one.
func RateLimitCount(key string, window time.Duration) (int, error) {
	var hits int
	err := GetDatabaseConnection().QueryRow(
		`SELECT COALESCE(max(hits), 0) FROM rate_limit WHERE key = $1 AND window_start = `+windowStartSQL,
		key, window.Seconds()).Scan(&hits)
	return hits, err
}

// RateLimitReset forgets the current window for key (e.g. after a successful login).
func RateLimitReset(key string, window time.Duration) error {
	_, err := GetDatabaseConnection().Exec(
		`DELETE FROM rate_limit WHERE key = $1 AND window_start = `+windowStartSQL, key, window.Seconds())
	return err
}
