package api_test

import (
	"net/http"
	"testing"

	"siemlite/api"
	"siemlite/pkg/auth"
)

func behindCaddy(t *testing.T, defaultDomain string) *env {
	t.Helper()
	p, _ := api.ParseProxies("127.0.0.1, ::1") // the test client plays Caddy
	return newEnvWith(t, func(d *api.Deps) { d.Proxies, d.BehindProxy, d.Domain = p, true, defaultDomain })
}

func ask(e *env, domain string, hdr map[string]string) int {
	return e.do(e.client(), "GET", "/api/v1/caddy/ask?domain="+domain, "", hdr).StatusCode
}

func TestPublicDomainSetting(t *testing.T) {
	e := behindCaddy(t, "")
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)

	var v map[string]any
	if got := e.call(root, "GET", "/api/v1/system/public", nil, &v, nil); got != 200 || v["domain"] != "" || v["behind_caddy"] != true {
		t.Fatalf("empty = %d %v", got, v)
	}
	// Caddy may not get a certificate for anything yet.
	if got := ask(e, "siem.example.com", nil); got != 404 {
		t.Errorf("ask with nothing set = %d", got)
	}
	for _, bad := range []string{"https://siem.example.com", "203.0.113.4", "localhost", "intranet"} {
		var er map[string]string
		if got := e.call(root, "PUT", "/api/v1/system/public", map[string]string{"domain": bad}, &er, nil); got != 400 || er["error"] == "" {
			t.Errorf("%q = %d %v", bad, got, er)
		}
	}
	if got := e.call(root, "PUT", "/api/v1/system/public", map[string]string{"domain": "SIEM.Example.com"}, &v, nil); got != 200 || v["domain"] != "siem.example.com" || v["from"] != "system" {
		t.Fatalf("save = %d %v", got, v)
	}
	// Caddy may now get a certificate for exactly that name.
	if got := ask(e, "siem.example.com", nil); got != 200 {
		t.Errorf("ask for the domain = %d", got)
	}
	for _, other := range []string{"evil.example.com", "example.com", "www.siem.example.com", ""} {
		if got := ask(e, other, nil); got != 404 {
			t.Errorf("ask for %q = %d", other, got)
		}
	}
	// Only Caddy itself may ask: a visitor's request passed through Caddy can't.
	if got := ask(e, "siem.example.com", map[string]string{"X-Forwarded-For": "203.0.113.9"}); got != 403 {
		t.Errorf("ask through the proxy = %d", got)
	}
	// Clearing it.
	if got := e.call(root, "PUT", "/api/v1/system/public", map[string]string{"domain": ""}, &v, nil); got != 200 || v["domain"] != "" {
		t.Errorf("clear = %d %v", got, v)
	}
	if got := ask(e, "siem.example.com", nil); got != 404 {
		t.Errorf("ask after clearing = %d", got)
	}
}

func TestPublicDomainFromSetting(t *testing.T) {
	e := behindCaddy(t, "Siem.Example.Org")
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	var v map[string]any
	if e.call(root, "GET", "/api/v1/system/public", nil, &v, nil); v["domain"] != "siem.example.org" || v["from"] != "setting" {
		t.Errorf("SIEMLITE_DOMAIN default = %v", v)
	}
	if got := ask(e, "siem.example.org", nil); got != 200 {
		t.Errorf("ask for SIEMLITE_DOMAIN = %d", got)
	}
	// The System page wins once something is saved there.
	e.call(root, "PUT", "/api/v1/system/public", map[string]string{"domain": "siem.example.com"}, nil, nil)
	if got := ask(e, "siem.example.org", nil); got != 404 {
		t.Errorf("the old default still allowed = %d", got)
	}
}

func TestAskIsRefusedWithoutAProxy(t *testing.T) {
	e := newEnvWith(t, func(d *api.Deps) { d.Domain = "siem.example.com" })
	if got := ask(e, "siem.example.com", nil); got != 403 {
		t.Errorf("ask from an untrusted address = %d", got)
	}
}

// Through Caddy, any other name is sent to the public domain; direct requests
// (the health check, loggen) are not.
func TestOtherNamesRedirectToThePublicDomain(t *testing.T) {
	e := behindCaddy(t, "siem.example.com")
	c := e.client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	get := func(host string, xff bool) *http.Response {
		req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/auth/providers?x=1", nil)
		req.Host = host
		if xff {
			req.Header.Set("X-Forwarded-For", "203.0.113.9")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := get("old.example.com", true); r.StatusCode != 308 || r.Header.Get("Location") != "https://siem.example.com/api/v1/auth/providers?x=1" {
		t.Errorf("old name = %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if r := get("siem.example.com", true); r.StatusCode != 200 {
		t.Errorf("the domain = %d", r.StatusCode)
	}
	if r := get("SIEM.example.com:443", true); r.StatusCode != 200 {
		t.Errorf("the domain with a port and capitals = %d", r.StatusCode)
	}
	if r := get("siemlite:8443", false); r.StatusCode != 200 {
		t.Errorf("a direct request inside Docker was redirected = %d", r.StatusCode)
	}
	// Not behind a proxy: never redirected.
	plain := newEnvWith(t, func(d *api.Deps) { d.Domain = "siem.example.com" })
	req, _ := http.NewRequest("GET", plain.srv.URL+"/api/v1/auth/providers", nil)
	req.Host = "other.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	pc := plain.client()
	pc.CheckRedirect = c.CheckRedirect
	if resp, err := pc.Do(req); err != nil || resp.StatusCode != 200 {
		t.Errorf("a forged header without a proxy caused a redirect: %v %v", resp.StatusCode, err)
	}
}
