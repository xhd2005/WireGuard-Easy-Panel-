package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempCredPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "credentials.json")
}

func TestNewManagerFirstRunGeneratesPassword(t *testing.T) {
	p := tempCredPath(t)
	m, initPass, err := NewManager(p, time.Hour)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if len(initPass) != 20 {
		t.Errorf("expected 20-char password, got %d chars: %q", len(initPass), initPass)
	}
	if !m.MustChangePassword() {
		t.Error("expected MustChangePassword=true on first run")
	}
	// File should exist with 0600 permissions
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 perm, got %v", fi.Mode().Perm())
	}

	// Login with generated password should succeed
	token, sess, err := m.Authenticate("admin", initPass, "127.0.0.1:12345")
	if err != nil {
		t.Fatalf("auth with init password failed: %v", err)
	}
	if token == "" || sess == nil {
		t.Fatal("empty token or session")
	}
	if !sess.MustChangePassword {
		t.Error("session should reflect MustChangePassword=true")
	}
}

func TestAuthenticateFailsAndRateLimits(t *testing.T) {
	p := tempCredPath(t)
	m, initPass, err := NewManager(p, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	ip := "192.168.1.100:54321"

	// 4 wrong attempts should fail with "用户名或密码错误"
	for i := 1; i <= 4; i++ {
		_, _, err := m.Authenticate("admin", "wrong", ip)
		if err == nil {
			t.Fatalf("attempt %d should fail", i)
		}
	}

	// 5th wrong attempt should trigger rate limiting
	_, _, err = m.Authenticate("admin", "wrong", ip)
	if err == nil {
		t.Fatal("5th attempt should fail")
	}

	// 6th attempt even with CORRECT password should be blocked by rate limiter
	_, _, err = m.Authenticate("admin", initPass, ip)
	if err == nil {
		t.Fatal("should be blocked by rate limiter")
	}

	// But a different IP with correct password should succeed!
	_, _, err = m.Authenticate("admin", initPass, "10.0.0.1:54321")
	if err != nil {
		t.Fatalf("different IP should succeed: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	p := tempCredPath(t)
	m, initPass, err := NewManager(p, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	token, sess, err := m.Authenticate("admin", initPass, "127.0.0.1:5000")
	if err != nil {
		t.Fatal(err)
	}
	if !sess.MustChangePassword {
		t.Fatal("initially must change password")
	}

	// Too short new password rejected
	if err := m.ChangePassword("admin", initPass, "short"); err == nil {
		t.Fatal("short password should be rejected")
	}

	// Wrong old password rejected
	if err := m.ChangePassword("admin", "wrong-old", "newPassword123456"); err == nil {
		t.Fatal("wrong old password should be rejected")
	}

	// Correct password change
	if err := m.ChangePassword("admin", initPass, "newPassword123456"); err != nil {
		t.Fatalf("change password failed: %v", err)
	}

	if m.MustChangePassword() {
		t.Error("MustChangePassword should be false after change")
	}

	// Re-validating existing session should show MustChangePassword=false
	s2, ok := m.ValidateSession(token)
	if !ok {
		t.Fatal("session should still be valid")
	}
	if s2.MustChangePassword {
		t.Error("session MustChangePassword should now be false")
	}

	// Old password should no longer work
	if _, _, err := m.Authenticate("admin", initPass, "127.0.0.1:5000"); err == nil {
		t.Error("old password should fail")
	}

	// New password should work
	if _, _, err := m.Authenticate("admin", "newPassword123456", "127.0.0.1:5000"); err != nil {
		t.Errorf("new password should succeed: %v", err)
	}
}

func TestSessionExpiryAndDestroy(t *testing.T) {
	p := tempCredPath(t)
	m, initPass, err := NewManager(p, 50*time.Millisecond) // short TTL
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := m.Authenticate("admin", initPass, "127.0.0.1:5000")
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := m.ValidateSession(token); !ok {
		t.Fatal("session should be valid immediately")
	}

	// Explicit destroy
	m.DestroySession(token)
	if _, ok := m.ValidateSession(token); ok {
		t.Fatal("session should be destroyed")
	}

	// New session, test expiration
	token2, _, err := m.Authenticate("admin", initPass, "127.0.0.1:5000")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(70 * time.Millisecond)
	if _, ok := m.ValidateSession(token2); ok {
		t.Fatal("session should have expired")
	}
}
