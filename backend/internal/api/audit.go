package api

import (
	"net/http"
	"regexp"
	"strconv"

	"guardian/internal/httpx"
	db "guardian/internal/store"
)

var eventTypeRe = regexp.MustCompile(`^[a-z_]+(\.[a-z_]+)*$`)

// listAudit returns the audit log, newest first. ?event= filters on one event type, ?account= on the
// account that acted; ?cursor= continues from next_cursor; ?limit= is 1-200 (default 50).
func listAudit(w http.ResponseWriter, r *http.Request) {
	limit, ok := pageLimit(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := db.AuditFilter{EventType: q.Get("event"), AccountID: q.Get("account"), About: q.Get("about"), Limit: limit + 1}
	if f.EventType != "" && (len(f.EventType) > 64 || !eventTypeRe.MatchString(f.EventType)) {
		httpx.Error(w, http.StatusBadRequest, "event must be an event type such as login.failure")
		return
	}
	if (f.AccountID != "" && !db.IsUUID(f.AccountID)) || (f.About != "" && !db.IsUUID(f.About)) {
		httpx.Error(w, http.StatusBadRequest, "account and about must be account ids")
		return
	}
	if c := q.Get("cursor"); c != "" {
		n, err := strconv.ParseInt(c, 10, 64)
		if err != nil || n < 1 {
			httpx.Error(w, http.StatusBadRequest, "cursor must be a next_cursor value from a previous page")
			return
		}
		f.Before = n
	}
	entries, err := db.ListAudit(f)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Failed to read the audit log")
		return
	}
	resp := map[string]any{"next_cursor": nil}
	if len(entries) > limit {
		entries = entries[:limit]
		resp["next_cursor"] = strconv.FormatInt(entries[limit-1].ID, 10)
	}
	resp["items"] = entries
	httpx.JSON(w, http.StatusOK, resp)
}
