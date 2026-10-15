package api

import "testing"

func TestNormalizeDomain(t *testing.T) {
	good := map[string]string{
		"siem.example.com":    "siem.example.com",
		" SIEM.Example.COM. ": "siem.example.com",
		"a-b.c-d.example.org": "a-b.c-d.example.org",
		"xn--bcher-kva.ch":    "xn--bcher-kva.ch",
		"":                    "",
	}
	for in, want := range good {
		if got, err := normalizeDomain(in); err != nil || got != want {
			t.Errorf("%q = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"https://siem.example.com", "siem.example.com:443", "siem.example.com/x", "203.0.113.4", "::1",
		"localhost", "siem.localhost", "intranet", "-bad.example.com", "bad-.example.com", "under_score.example.com",
		"*.example.com", "a..example.com", "user@example.com", "two words.example.com"} {
		if _, err := normalizeDomain(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
