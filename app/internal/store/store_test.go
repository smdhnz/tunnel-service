package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestMutationsRequireExistingRow(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for name, mutate := range map[string]func() error{
		"user status":      func() error { return st.SetUserStatus(ctx, 999, "suspended") },
		"key status":       func() error { return st.SetKeyEnabled(ctx, 999, false) },
		"key delete":       func() error { return st.DeleteKey(ctx, 999) },
		"subdomain delete": func() error { return st.DeleteSubdomain(ctx, 999) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := mutate(); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("want sql.ErrNoRows, got %v", err)
			}
		})
	}
}
