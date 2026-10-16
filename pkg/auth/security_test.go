package auth

// Security regression checks for the auth package (see api/security_test.go
// for the suite's shape, and SECURITY-AUDIT.md for the findings).

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"siemlite/pkg/storage"
)

var securityChecks = []struct {
	name string
	run  func(t *testing.T)
}{
	{"limiter-memory-is-bounded", checkLimiterBounded},
	{"unknown-usernames-stay-out-of-logs", checkUnknownUsernameNotLogged},
	{"generated-passwords-are-uniform", checkGeneratedPassword},
}

func TestSecurity(t *testing.T) {
	for _, c := range securityChecks {
		t.Run(c.name, c.run)
	}
}

// --- Finding: the sign-in limiter grew without bound ---

func checkLimiterBounded(t *testing.T) {
	l := newLoginLimiter(maxFailures)
	for i := 0; i < maxEntries+1000; i++ {
		l.fail(fmt.Sprintf("2001:db8::%x", i))
	}
	if n := l.size(); n > maxEntries {
		t.Errorf("remembers %d keys after a flood, cap is %d", n, maxEntries)
	}
	// A locked-out key is still locked out while the flood goes on.
	for i := 0; i < maxFailures; i++ {
		l.fail("192.0.2.1")
	}
	if l.allow("192.0.2.1") {
		t.Error("a locked-out address was allowed")
	}
	// Expired entries go first when room is needed.
	l.mu.Lock()
	for k, e := range l.entries {
		if k != "192.0.2.1" {
			e.first = time.Now().Add(-2 * failureWindow)
		}
	}
	l.mu.Unlock()
	l.fail("new-key")
	if n := l.size(); n != 2 {
		t.Errorf("after expired entries were dropped: %d keys, want 2", n)
	}
	if l.allow("192.0.2.1") {
		t.Error("the live lockout was dropped instead of an expired entry")
	}
}

// --- Finding: a password typed in the username field reached the log ---

func checkUnknownUsernameNotLogged(t *testing.T) {
	HashCost = bcrypt.MinCost
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := storage.NewRepository(db)
	var buf bytes.Buffer
	a := New(repo, slog.New(slog.NewTextHandler(&buf, nil)))
	if _, err := CreateUser(ctx, repo, "alice", "correct horse battery", RoleStandard); err != nil {
		t.Fatal(err)
	}

	const typo = "hunter2-my-real-password"
	if _, _, err := a.Login(ctx, "192.0.2.1", typo, "x"); err != ErrBadCredentials {
		t.Fatalf("login with a non-account name: %v", err)
	}
	if strings.Contains(buf.String(), typo) {
		t.Errorf("the log repeats what was typed as the username: %s", buf.String())
	}
	buf.Reset()
	if _, _, err := a.Login(ctx, "192.0.2.1", "alice", "wrong"); err != ErrBadCredentials {
		t.Fatalf("login with a wrong password: %v", err)
	}
	if !strings.Contains(buf.String(), "user=alice") {
		t.Errorf("a failure for a real account should name it: %s", buf.String())
	}
}

// --- Finding: modulo bias in generated passwords ---

func checkGeneratedPassword(t *testing.T) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 20 {
			t.Fatalf("password %q has %d characters, want 20", pw, len(pw))
		}
		if strings.Trim(pw, alphabet) != "" {
			t.Fatalf("password %q uses characters outside the alphabet", pw)
		}
		if seen[pw] {
			t.Fatalf("password %q generated twice", pw)
		}
		seen[pw] = true
	}
}
