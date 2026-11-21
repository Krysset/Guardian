package web

import (
	"log/slog"
	"net/http"

	"guardian/internal/httpx"
	db "guardian/internal/store"
)

// homePage is H0 at /, where a signed-in user lands: their connected apps and the apps available to them,
// each opening the app's homepage. It shows no personal details beyond the username. This simple version
// in the sign-in page style stands in until the management UI brings the full Home in 0.4.
func homePage(w http.ResponseWriter, r *http.Request) {
	sess, ok := httpx.SessionFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	acct, err := db.GetAccount(sess.AccountID)
	if err != nil {
		Error(w, ServerError)
		return
	}
	if acct.MustChangePassword {
		http.Redirect(w, r, MustChangePasswordURL(""), http.StatusFound)
		return
	}
	apps, err := db.AppsForHome(acct.ID)
	if err != nil {
		slog.Error("failed to list the apps for Home", "error", err)
		Error(w, ServerError)
		return
	}
	page := Page{Title: "Home", Username: acct.Username, CSRF: httpx.CSRFToken(w, r)}
	for _, a := range apps {
		if a.Connected {
			page.Connected = append(page.Connected, a.App)
		} else {
			page.Available = append(page.Available, a.App)
		}
	}
	Render(w, http.StatusOK, "home", page)
}
