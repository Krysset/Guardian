package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"guardian/internal/httpx"
	"guardian/internal/mail"
	db "guardian/internal/store"
)

// Requests to join a group (A33): made from the account area or from the no-access page (S7), decided by
// the group's owners, or by Guardian admins when it has no owner group. Both sides are told by email.

const (
	// requestsPerHour limits how many requests one account makes, so asking cannot be used to spam the
	// people who decide.
	requestsPerHour = 10
	// MaxRequestMessage is the longest message a request may carry.
	MaxRequestMessage = 500
)

// ErrTooManyRequests: the account asked too often in the last hour.
var ErrTooManyRequests = errors.New("too many requests to join groups in the last hour; try again later")

// AskToJoin records the signed-in account's request to join a group and tells the people who decide.
func AskToJoin(r *http.Request, accountID, groupID, message string) (db.GroupRequest, error) {
	message = strings.TrimSpace(message)
	if utf8.RuneCountInString(message) > MaxRequestMessage {
		message = string([]rune(message)[:MaxRequestMessage])
	}
	n, err := db.RateLimitHit("group-request:account:"+accountID, time.Hour)
	if err != nil {
		return db.GroupRequest{}, err
	}
	if n > requestsPerHour {
		httpx.CountRefused("group_request")
		return db.GroupRequest{}, ErrTooManyRequests
	}
	q, err := db.RequestGroup(accountID, groupID, message)
	if err != nil {
		return db.GroupRequest{}, err
	}
	db.Audit("group.request_made", accountID, "", httpx.ClientIP(r), map[string]any{"group": groupID, "request": q.ID})
	who := q.Username
	if q.DisplayName != "" {
		who = q.DisplayName + " (" + q.Username + ")"
	}
	deciders, err := db.GroupDeciders(groupID)
	if err != nil {
		slog.Error("failed to find who decides a group request", "error", err)
	}
	group, _ := db.GetGroup(groupID)
	for _, d := range deciders {
		link := httpx.Issuer + "/account/groups/" + groupID
		if group.OwnerGroupID == "" {
			link = httpx.Issuer + "/admin/groups/" + groupID
		}
		mail.Enqueue(mail.GroupRequested(d.Email, who, q.GroupName, message, link, q.CreatedAt, d.Zoneinfo))
	}
	return q, nil
}

// DecideRequest approves or denies a request of the group, audits it, and tells the requester.
func DecideRequest(r *http.Request, groupID, requestID, via string, approve bool, expiresAt *time.Time) (db.GroupRequest, error) {
	by := httpx.AccountID(r)
	q, err := db.DecideGroupRequest(groupID, requestID, by, approve, expiresAt)
	if err != nil {
		return db.GroupRequest{}, err
	}
	meta := map[string]any{"group": groupID, "request": requestID, "target": q.AccountID, "via": via}
	if approve {
		if expiresAt != nil {
			meta["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
		}
		db.Audit("group.request_approved", by, "", httpx.ClientIP(r), meta)
	} else {
		db.Audit("group.request_denied", by, "", httpx.ClientIP(r), meta)
	}
	if acct, err := db.GetAccount(q.AccountID); err == nil && acct.Email != "" && acct.EmailVerified {
		mail.Enqueue(mail.GroupRequestDecided(acct.Email, q.GroupName, approve, httpx.Issuer+"/account/groups", time.Now(), acct.Zoneinfo))
	}
	return q, nil
}

// requestAccessSubmit is "Ask to join" on the no-access page (S7): it asks for one of the app's requestable
// groups and shows the page again with what happened.
func requestAccessSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	sess, ok := httpx.SessionFromRequest(r)
	if !ok || !httpx.CSRFValid(r) {
		Error(w, FormExpired)
		return
	}
	returnTo := httpx.SafeReturnTo(r.PostFormValue("return_to"))
	_, err := AskToJoin(r, sess.AccountID, r.PostFormValue("group"), r.PostFormValue("message"))
	outcome := "sent"
	switch {
	case errors.Is(err, db.ErrAlreadyRequested):
		outcome = "already"
	case errors.Is(err, ErrTooManyRequests):
		outcome = "limit"
	case errors.Is(err, db.ErrNotRequestable):
		outcome = "closed"
	case err != nil:
		slog.Error("failed to record a group request", "error", err)
		Error(w, ServerError)
		return
	}
	if returnTo == "" {
		http.Redirect(w, r, "/account/groups", http.StatusSeeOther)
		return
	}
	// Back to the app's sign-in, which shows the no-access page again with what happened.
	http.Redirect(w, r, returnTo+"&requested="+outcome, http.StatusSeeOther)
}

// RequestNotice is what the no-access page says after "Ask to join" (requested=...), or "".
func RequestNotice(outcome string) string {
	switch outcome {
	case "sent":
		return "Your request was sent. You get an email when it is decided."
	case "already":
		return "You have asked to join that group already. You get an email when it is decided."
	case "limit":
		return "You have asked too many times in the last hour. Try again later."
	case "closed":
		return "That group can no longer be asked for."
	}
	return ""
}
