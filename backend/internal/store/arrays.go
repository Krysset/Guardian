package store

import (
	"database/sql"
	"sync"

	"github.com/jackc/pgx/v5/pgtype"
)

// strArray prepares a string slice for use as a text[] query argument. A nil slice becomes an empty
// array instead of NULL, so an optional list (for example post_logout_redirect_uris left out of a
// request) fits a NOT NULL column.
func strArray(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// scanArray returns a Scan target that reads a Postgres text[] value into dst. database/sql cannot
// scan arrays by itself.
func scanArray(dst *[]string) sql.Scanner {
	return arrayScanner{dst}
}

type arrayScanner struct{ dst *[]string }

// typeMaps holds pgx type maps for decoding arrays. A type map caches scan plans and is not safe for
// concurrent use, so each Scan borrows one.
var typeMaps = sync.Pool{New: func() any { return pgtype.NewMap() }}

func (a arrayScanner) Scan(src any) error {
	m := typeMaps.Get().(*pgtype.Map)
	defer typeMaps.Put(m)
	return m.SQLScanner(a.dst).Scan(src)
}
