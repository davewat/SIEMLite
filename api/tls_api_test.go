package api_test

import (
	"strings"
	"testing"
	"time"

	"siemlite/pkg/auth"
)

func TestCertificateSettingAPI(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)

	var v map[string]any
	if got := e.call(root, "GET", "/api/v1/system/tls", nil, &v, nil); got != 200 || v["mode"] != "self-signed" {
		t.Fatalf("default = %d %v", got, v)
	}
	if sc, _ := v["self_signed_certificate"].(map[string]any); sc == nil || sc["self_signed"] != true {
		t.Errorf("self-signed certificate info = %v", v["self_signed_certificate"])
	}
	for _, bad := range []map[string]string{{"mode": "letsencrypt"}, {"mode": "letsencrypt", "domain": "https://x.example.com"},
		{"mode": "letsencrypt", "domain": "203.0.113.4"}, {"mode": "other"}} {
		var er map[string]string
		if got := e.call(root, "PUT", "/api/v1/system/tls", bad, &er, nil); got != 400 || er["error"] == "" {
			t.Errorf("%v = %d %v", bad, got, er)
		}
	}
	// Let's Encrypt that can't be reached: saved, and the reason shows up.
	if got := e.call(root, "PUT", "/api/v1/system/tls", map[string]string{"mode": "letsencrypt", "domain": "Siem.Example.com"}, &v, nil); got != 200 || v["mode"] != "letsencrypt" || v["domain"] != "siem.example.com" {
		t.Fatalf("save = %d %v", got, v)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		e.call(root, "GET", "/api/v1/system/tls", nil, &v, nil)
		if s, _ := v["last_error"].(string); strings.Contains(s, "Let's Encrypt") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no explanation after failing: %v", v)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The site is still reachable meanwhile: this very request used the self-signed certificate.
	if got := e.call(root, "GET", "/api/v1/me", nil, nil, nil); got != 200 {
		t.Errorf("signed out or unreachable after choosing Let's Encrypt = %d", got)
	}
	if got := e.call(root, "PUT", "/api/v1/system/tls", map[string]string{"mode": "self-signed"}, &v, nil); got != 200 || v["mode"] != "self-signed" {
		t.Errorf("back to self-signed = %d %v", got, v)
	}
	// The check needs a domain; the echo answers only tokens the server issued.
	var er map[string]string
	if got := e.call(root, "POST", "/api/v1/system/tls/check", map[string]string{"domain": "localhost"}, &er, nil); got != 400 {
		t.Errorf("check localhost = %d %v", got, er)
	}
	if got := e.do(e.client(), "GET", "/.well-known/siemlite-check/0123456789abcdef", "", nil).StatusCode; got != 404 {
		t.Errorf("unknown token = %d", got)
	}
}
