package integration

import (
	"os"
	"path/filepath"
	"testing"

	"tunnel-control-plane/internal/model"
)

func TestReconcileOnlyRemovesPrefixedManagedKeys(t *testing.T) {
	dir := t.TempDir()
	manual := filepath.Join(dir, "legacy-user.pub")
	numericManual := filepath.Join(dir, "9-9.pub")
	for path, content := range map[string]string{manual: "legacy\n", numericManual: "manual numeric\n"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	w := PublicKeyWriter{Dir: dir}
	stale := model.SSHKey{ID: 2, UserID: 1, PublicKey: "ssh-ed25519 AAAA"}
	if err := w.Write(stale); err != nil {
		t.Fatal(err)
	}
	if err := w.Reconcile(nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{manual, numericManual} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("manual key removed: %s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "control-plane-1-2.pub")); !os.IsNotExist(err) {
		t.Fatalf("stale managed key remains: %v", err)
	}
}

func TestWriteUsesReservedPrefixWithoutTouchingNumericManualKey(t *testing.T) {
	dir := t.TempDir()
	manual := filepath.Join(dir, "1-2.pub")
	if err := os.WriteFile(manual, []byte("manual\n"), 0600); err != nil {
		t.Fatal(err)
	}
	w := PublicKeyWriter{Dir: dir}
	if err := w.Write(model.SSHKey{ID: 2, UserID: 1, PublicKey: "managed"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(manual)
	if err != nil || string(got) != "manual\n" {
		t.Fatalf("manual key changed: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "control-plane-1-2.pub")); err != nil {
		t.Fatalf("managed key missing: %v", err)
	}
}
