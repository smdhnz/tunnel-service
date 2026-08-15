package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"tunnel-control-plane/internal/model"
)

type PublicKeyWriter struct{ Dir string }

const managedKeyPrefix = "control-plane-"

var managedKeyFile = regexp.MustCompile(`^control-plane-[1-9][0-9]*-[1-9][0-9]*\.pub$`)

func (w PublicKeyWriter) filename(userID, keyID int64) string {
	return filepath.Join(w.Dir, managedKeyPrefix+strconv.FormatInt(userID, 10)+"-"+strconv.FormatInt(keyID, 10)+".pub")
}

func (w PublicKeyWriter) Write(k model.SSHKey) error {
	if k.ID <= 0 || k.UserID <= 0 {
		return fmt.Errorf("invalid numeric key identifiers")
	}
	if err := os.MkdirAll(w.Dir, 0750); err != nil {
		return err
	}
	return w.atomicWrite(w.filename(k.UserID, k.ID), strings.TrimSpace(k.PublicKey)+"\n", 0640)
}

func (w PublicKeyWriter) Remove(userID, keyID int64) error {
	if userID <= 0 || keyID <= 0 {
		return fmt.Errorf("invalid numeric key identifiers")
	}
	err := os.Remove(w.filename(userID, keyID))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDir(w.Dir)
}

func (w PublicKeyWriter) Reconcile(keys []model.SSHKey) error {
	if err := os.MkdirAll(w.Dir, 0750); err != nil {
		return err
	}
	wanted := make(map[string]model.SSHKey, len(keys))
	for _, k := range keys {
		wanted[filepath.Base(w.filename(k.UserID, k.ID))] = k
	}
	entries, err := os.ReadDir(w.Dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		// The prefix is a reserved Control Plane namespace. Never infer
		// ownership from a numeric-looking filename such as 1-2.pub.
		if entry.IsDir() || !managedKeyFile.MatchString(entry.Name()) {
			continue
		}
		if _, ok := wanted[entry.Name()]; ok {
			continue
		}
		if err = os.Remove(filepath.Join(w.Dir, entry.Name())); err != nil {
			return err
		}
	}
	for _, k := range wanted {
		if err = w.Write(k); err != nil {
			return err
		}
	}
	return syncDir(w.Dir)
}

func (w PublicKeyWriter) atomicWrite(target, content string, mode os.FileMode) error {
	tmp, err := os.CreateTemp(w.Dir, ".control-plane-tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.WriteString(content)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, target); err != nil {
		return err
	}
	return syncDir(w.Dir)
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

type TunnelProvider interface{ ActiveCount() (int, error) }
type UnavailableTunnelProvider struct{}

func (UnavailableTunnelProvider) ActiveCount() (int, error) {
	return 0, fmt.Errorf("active tunnel data unavailable")
}
