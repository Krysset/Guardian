package backup

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	db "guardian/internal/store"
)

// The deletion log as a file: `guardian deletions export` writes it, `guardian restore --apply-deletions`
// reads it, so accounts erased after a backup was taken stay erased when it is restored. It holds account
// ids and times only.
//
//	GUARDIAN-DELETIONS 1
//	{"account_id":"...","erased_at":"..."}
//	...

const deletionsMagic = "GUARDIAN-DELETIONS 1"

// WriteDeletions writes the deletion log.
func WriteDeletions(w io.Writer, deletions []db.Deletion) error {
	bw := bufio.NewWriter(w)
	fmt.Fprintln(bw, deletionsMagic)
	enc := json.NewEncoder(bw)
	for _, d := range deletions {
		if err := enc.Encode(d); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// ReadDeletions reads a deletion log file.
func ReadDeletions(r io.Reader) ([]db.Deletion, error) {
	sc := bufio.NewScanner(r)
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != deletionsMagic {
		return nil, errors.New("not a Guardian deletion log (the first line is wrong)")
	}
	var out []db.Deletion
	for line := 2; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var d db.Deletion
		if err := json.Unmarshal([]byte(text), &d); err != nil || !db.IsUUID(d.AccountID) {
			return nil, fmt.Errorf("deletion log line %d is not an entry", line)
		}
		out = append(out, d)
	}
	return out, sc.Err()
}

// applyDeletions erases, inside tx, the accounts of the deletion log that the restored data still holds,
// and records every entry in the restored deletion log. It returns how many accounts it erased.
func applyDeletions(ctx context.Context, tx *sql.Tx, deletions []db.Deletion) (int, error) {
	erased := 0
	for _, d := range deletions {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM account WHERE id = $1)`, d.AccountID).Scan(&exists); err != nil {
			return erased, err
		}
		if err := db.EraseAccountTx(tx, d.AccountID); err != nil {
			return erased, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE deletion_log SET erased_at = LEAST(erased_at, $2) WHERE account_id = $1`,
			d.AccountID, d.ErasedAt); err != nil {
			return erased, err
		}
		if exists {
			erased++
		}
	}
	return erased, nil
}

func printDeletions(w io.Writer, deletions []db.Deletion, erased int) {
	if len(deletions) > 0 {
		fmt.Fprintf(w, "Deletion log applied: %d entries, %d accounts erased that the backup still held.\n", len(deletions), erased)
	}
}

// ExportDeletions writes the database's deletion log to w.
func ExportDeletions(ctx context.Context, conn *sql.DB, w io.Writer) (int, error) {
	deletions, err := db.ListDeletions(ctx, conn)
	if err != nil {
		return 0, err
	}
	return len(deletions), WriteDeletions(w, deletions)
}
