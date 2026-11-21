package api

import (
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"guardian/internal/httpx"
)

// Routes that are not for administrators only. Everything else under /api/v1 must be behind httpx.AdminOnly,
// so a new route is refused to ordinary users unless it is added here on purpose.
var (
	// No session needed: open sign-up (rate limited per address).
	openRoutes = map[string]bool{"POST /signup": true, "GET /signup/challenge": true}
	// Any signed-in user: their own account, groups (the handlers let a group's owners in, and only them),
	// and apps and their audit entries (the handlers let an app's admins in, and only them).
	userRoutes = map[string]bool{
		"GET /groups": true, "GET /groups/{group}": true, "GET /groups/{group}/members": true,
		"POST /groups/{group}/members": true, "PUT /groups/{group}/members/{account}": true,
		"DELETE /groups/{group}/members/{account}": true,
		"GET /groups/{group}/requests":             true, "POST /groups/{group}/requests/{request}": true,
		"GET /apps": true, "GET /apps/{app}": true, "PATCH /apps/{app}": true, "PUT /apps/{app}/access": true,
		"POST /apps/{app}/secret": true, "GET /audit": true, "GET /scopes": true,
	}
)

func uses(mws []func(http.Handler) http.Handler, want func(http.Handler) http.Handler) bool {
	p := reflect.ValueOf(want).Pointer()
	for _, mw := range mws {
		if reflect.ValueOf(mw).Pointer() == p {
			return true
		}
	}
	return false
}

// Every /api/v1 route is behind sign-in (the machine API behind the app's own credentials), and every
// route that is not deliberately open to users is behind the administrators' check.
//
// Covers: A12, A22, O3
func TestEveryRouteHasItsPermissionCheck(t *testing.T) {
	var problems []string
	n := 0
	err := chi.Walk(Router().(chi.Routes), func(method, route string, _ http.Handler, mws ...func(http.Handler) http.Handler) error {
		route = strings.TrimSuffix(strings.ReplaceAll(route, "/*/", "/"), "/")
		key := method + " " + route
		n++
		switch {
		case strings.HasPrefix(route, "/apps/self"):
			// The machine API: Bearer credentials of the app itself, checked in its own router.
		case openRoutes[key]:
			if uses(mws, httpx.Authenticate) {
				problems = append(problems, key+" is meant to be open but requires a session")
			}
		case !uses(mws, httpx.Authenticate):
			problems = append(problems, key+" does not require a session")
		case strings.HasPrefix(route, "/me") || userRoutes[key]:
			if uses(mws, httpx.AdminOnly) {
				problems = append(problems, key+" is meant for every user but is for administrators only")
			}
		case !uses(mws, httpx.AdminOnly):
			problems = append(problems, key+" is open to every signed-in user: add httpx.AdminOnly, or list it in userRoutes on purpose")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 40 {
		t.Fatalf("walked only %d routes", n)
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}
