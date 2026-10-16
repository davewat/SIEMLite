package web

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecurity guards the audit findings in this package: the policy allows
// exactly the page's inline scripts, and folders aren't listed.
func TestSecurity(t *testing.T) {
	t.Run("csp-matches-the-page", func(t *testing.T) {
		page, err := assets.ReadFile("static/index.html")
		if err != nil {
			t.Fatal(err)
		}
		csp := ContentSecurityPolicy()
		scripts := inlineScripts(page)
		if len(scripts) < 1 {
			t.Fatal("no inline scripts found in index.html")
		}
		for i, s := range scripts {
			sum := sha256.Sum256(s)
			if h := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; !strings.Contains(csp, h) {
				t.Errorf("script %d not allowed by %q", i, csp)
			}
		}
		if strings.Contains(csp, "unsafe-eval") || strings.Contains(strings.Split(csp, "style-src")[0], "unsafe-inline") {
			t.Errorf("policy allows inline or eval script: %q", csp)
		}
	})
	t.Run("no-directory-listing", func(t *testing.T) {
		h := Handler()
		for path, want := range map[string]int{"/fonts/": 404, "/fonts/instrument-sans.woff2": 200, "/": 200, "/index.html": 301} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != want {
				t.Errorf("GET %s: %d, want %d", path, rec.Code, want)
			}
		}
	})
}
