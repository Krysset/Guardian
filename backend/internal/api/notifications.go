package api

import (
	"log/slog"
	"net/http"
	"slices"

	"guardian/internal/httpx"
	db "guardian/internal/store"
	"guardian/internal/web"
)

// notificationsView is AC9: where emails go, and how each kind of notification the account can receive
// comes.
type notificationsView struct {
	Email       string                `json:"email"` // "" without a confirmed address
	SummaryHour int                   `json:"summary_hour"`
	Settings    []notificationSetting `json:"settings"`
}

type notificationSetting struct {
	web.NotificationKind
	Delivery db.Delivery `json:"delivery"`
}

func notificationsOf(w http.ResponseWriter, accountID string) (notificationsView, bool) {
	fail := func(err error) (notificationsView, bool) {
		slog.Error("failed to read notification settings", "error", err)
		httpx.Error(w, http.StatusInternalServerError, "Request failed")
		return notificationsView{}, false
	}
	acct, err := db.GetAccount(accountID)
	if err != nil {
		return fail(err)
	}
	kinds, err := web.NotificationKindsFor(accountID)
	if err != nil {
		return fail(err)
	}
	chosen, hour, err := db.NotificationSettings(accountID)
	if err != nil {
		return fail(err)
	}
	v := notificationsView{SummaryHour: hour, Settings: []notificationSetting{}}
	if acct.EmailVerified {
		v.Email = acct.Email
	}
	for _, k := range kinds {
		d, ok := chosen[k.Key]
		if !ok {
			d = db.DeliveryNow
		}
		v.Settings = append(v.Settings, notificationSetting{k, d})
	}
	return v, true
}

func getMyNotifications(w http.ResponseWriter, r *http.Request) {
	if v, ok := notificationsOf(w, httpx.AccountID(r)); ok {
		httpx.JSON(w, http.StatusOK, v)
	}
}

// updateMyNotifications changes the given choices and, when sent, the summary hour. Only kinds the account
// can receive may be set.
func updateMyNotifications(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SummaryHour *int                   `json:"summary_hour"`
		Settings    map[string]db.Delivery `json:"settings"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if req.SummaryHour != nil && (*req.SummaryHour < 0 || *req.SummaryHour > 23) {
		httpx.Error(w, http.StatusBadRequest, "summary_hour must be a whole hour from 0 to 23")
		return
	}
	for _, d := range req.Settings {
		if d != db.DeliveryOff && d != db.DeliveryNow && d != db.DeliveryDaily {
			httpx.Error(w, http.StatusBadRequest, "Each setting must be off, now or daily")
			return
		}
	}
	id := httpx.AccountID(r)
	kinds, err := web.NotificationKindsFor(id)
	if err != nil {
		accountFail(w, err)
		return
	}
	for k := range req.Settings {
		if !slices.ContainsFunc(kinds, func(n web.NotificationKind) bool { return n.Key == k }) {
			httpx.Error(w, http.StatusBadRequest, "No notification "+k+" for this account")
			return
		}
	}
	if err := db.SetNotificationSettings(id, req.Settings, req.SummaryHour); err != nil {
		accountFail(w, err)
		return
	}
	db.Audit("account.notifications_changed", id, "", httpx.ClientIP(r), nil)
	if v, ok := notificationsOf(w, id); ok {
		httpx.JSON(w, http.StatusOK, v)
	}
}
