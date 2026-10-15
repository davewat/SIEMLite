package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealOpen(t *testing.T) {
	dir := t.TempDir()
	b := NewBox(filepath.Join(dir, "k.key"))
	sealed, err := b.Seal("hunter2 ünïcode")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "hunter2") || !strings.HasPrefix(sealed, "v1:") {
		t.Errorf("sealed = %q", sealed)
	}
	if got, err := b.Open(sealed); err != nil || got != "hunter2 ünïcode" {
		t.Errorf("Open = %q %v", got, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "k.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", fi, err)
	}
	// Two seals of the same text differ (random nonce).
	if again, _ := b.Seal("hunter2 ünïcode"); again == sealed {
		t.Error("sealing is deterministic")
	}
	// Another key can't open it; a damaged value is refused; a missing key never makes one on open.
	other := NewBox(filepath.Join(t.TempDir(), "other.key"))
	if _, err := other.Open(sealed); err == nil {
		t.Error("opened with a missing key")
	}
	if _, err := os.Stat(other.path); err == nil {
		t.Error("Open created a key file")
	}
	other.Seal("x")
	if _, err := other.Open(sealed); err == nil {
		t.Error("opened with a different key")
	}
	for _, bad := range []string{"", "v1:", "v1:!!!", "plain", "v1:" + strings.Repeat("A", 8)} {
		if _, err := b.Open(bad); err == nil {
			t.Errorf("Open(%q) succeeded", bad)
		}
	}
	if KeyPath("/data/siemlite.db") != "/data/siemlite-secret.key" {
		t.Errorf("KeyPath = %s", KeyPath("/data/siemlite.db"))
	}
}
