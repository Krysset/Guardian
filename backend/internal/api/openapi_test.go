package api

import (
	"bufio"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// specOperations reads "METHOD /path" for every operation in docs/openapi.yaml. It relies on the file's
// layout instead of a YAML parser (there is none among the dependencies): paths are the two-space
// indented keys under "paths:", and methods the four-space indented keys under a path.
func specOperations(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open("../../../docs/openapi.yaml")
	if err != nil {
		t.Fatalf("open the spec: %v", err)
	}
	defer f.Close()
	methods := map[string]bool{"get": true, "put": true, "post": true, "patch": true, "delete": true}
	ops := map[string]bool{}
	inPaths, path := false, ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "paths:":
			inPaths = true
		case inPaths && line != "" && !strings.HasPrefix(line, " "):
			inPaths = false // the next top-level key
		case inPaths && strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":"):
			path = strings.TrimSuffix(strings.TrimSpace(line), ":")
		case inPaths && path != "" && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     "):
			if key := strings.TrimSuffix(strings.TrimSpace(line), ":"); methods[key] {
				ops[strings.ToUpper(key)+" "+path] = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return ops
}

// TestOpenAPIDescribesEveryRoute keeps docs/openapi.yaml and the router in step: every route is
// documented, and nothing is documented that does not exist.
func TestOpenAPIDescribesEveryRoute(t *testing.T) {
	routes := map[string]bool{}
	err := chi.Walk(Router().(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.ReplaceAll(route, "/*/", "/")
		if route != "/" {
			route = strings.TrimSuffix(route, "/")
		}
		routes[method+" "+route] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	spec := specOperations(t)
	if len(spec) < 20 {
		t.Fatalf("read only %d operations from the spec; has its layout changed?", len(spec))
	}
	var missing, extra []string
	for r := range routes {
		if !spec[r] {
			missing = append(missing, r)
		}
	}
	for op := range spec {
		if !routes[op] {
			extra = append(extra, op)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	for _, r := range missing {
		t.Errorf("route not in docs/openapi.yaml: %s", r)
	}
	for _, op := range extra {
		t.Errorf("docs/openapi.yaml describes a route that does not exist: %s", op)
	}
}
