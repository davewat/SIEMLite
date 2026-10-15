package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func req(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for _, h := range xff {
		r.Header.Add("X-Forwarded-For", h)
	}
	return r
}

func TestParseProxies(t *testing.T) {
	p, err := ParseProxies(" 10.0.0.5, 172.16.0.0/12 ,caddy, ::1 ,")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Configured() || len(p.nets) != 3 || len(p.hosts) != 1 || p.hosts[0] != "caddy" {
		t.Errorf("parsed = %+v", p)
	}
	for _, bad := range []string{"10.0.0.0/99", "has space", "http://caddy", "a@b"} {
		if _, err := ParseProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	empty, _ := ParseProxies("")
	if empty.Configured() {
		t.Error("an empty list is configured")
	}
	var none *Proxies
	if none.Configured() || none.Trusted(netip.MustParseAddr("127.0.0.1")) {
		t.Error("a nil list trusts something")
	}
}

func TestClientIP(t *testing.T) {
	p, _ := ParseProxies("10.0.0.5, 10.0.1.0/24")
	cases := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"direct visitor", "203.0.113.9:5000", nil, "203.0.113.9"},
		{"direct visitor's own header is ignored", "203.0.113.9:5000", []string{"1.2.3.4"}, "203.0.113.9"},
		{"through the proxy", "10.0.0.5:4000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"a forged left-hand address doesn't count", "10.0.0.5:4000", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"two trusted hops", "10.0.0.5:4000", []string{"198.51.100.7, 10.0.1.9"}, "198.51.100.7"},
		{"forged hop that claims to be a proxy", "10.0.0.5:4000", []string{"6.6.6.6, 198.51.100.7, 10.0.1.9"}, "198.51.100.7"},
		{"headers split over lines", "10.0.0.5:4000", []string{"6.6.6.6", "198.51.100.7"}, "198.51.100.7"},
		{"proxy with no header", "10.0.0.5:4000", nil, "10.0.0.5"},
		{"garbage stops the walk", "10.0.0.5:4000", []string{"198.51.100.7, not-an-ip"}, "10.0.0.5"},
		{"everything trusted", "10.0.0.5:4000", []string{"10.0.1.2"}, "10.0.1.2"},
		{"IPv6 visitor", "10.0.0.5:4000", []string{"2001:db8::7"}, "2001:db8::7"},
		{"IPv4-mapped IPv6 proxy", "[::ffff:10.0.0.5]:4000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"no port", "203.0.113.9", nil, "203.0.113.9"},
	}
	for _, c := range cases {
		if got := p.ClientIP(req(c.remote, c.xff...)); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
	// With no proxies configured, the header is never believed.
	var none *Proxies
	if got := none.ClientIP(req("10.0.0.5:1", "198.51.100.7")); got != "10.0.0.5" {
		t.Errorf("no proxies: %s", got)
	}
}

func TestProxyHostNames(t *testing.T) {
	p, _ := ParseProxies("caddy")
	addrs := map[string][]netip.Addr{"caddy": {netip.MustParseAddr("172.18.0.4")}}
	p.lookup = func(_ context.Context, h string) ([]netip.Addr, error) {
		if a, ok := addrs[h]; ok {
			return a, nil
		}
		return nil, errors.New("no such host")
	}
	r := req("172.18.0.4:9000", "198.51.100.7")
	if got := p.ClientIP(r); got != "172.18.0.4" {
		t.Errorf("before the name is looked up: %s", got)
	}
	p.Refresh(context.Background())
	if got := p.ClientIP(r); got != "198.51.100.7" {
		t.Errorf("after lookup: %s", got)
	}
	// The container restarts with a new address: the old one stops being trusted.
	addrs["caddy"] = []netip.Addr{netip.MustParseAddr("172.18.0.9")}
	p.Refresh(context.Background())
	if got := p.ClientIP(r); got != "172.18.0.4" {
		t.Errorf("old address still trusted: %s", got)
	}
	if got := p.ClientIP(req("172.18.0.9:9000", "198.51.100.7")); got != "198.51.100.7" {
		t.Errorf("new address: %s", got)
	}
	// It stops resolving (the proxy is down): nothing is trusted.
	delete(addrs, "caddy")
	p.Refresh(context.Background())
	if p.Trusted(netip.MustParseAddr("172.18.0.9")) {
		t.Error("an unresolvable name is still trusted")
	}
}

func TestOnlyProxies(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	p, _ := ParseProxies("10.0.0.5")
	h := p.onlyProxies(ok)
	for remote, want := range map[string]int{"10.0.0.5:1": 200, "203.0.113.9:1": 403, "garbage": 403} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req(remote))
		if w.Code != want {
			t.Errorf("%s = %d, want %d", remote, w.Code, want)
		}
	}
	// Without proxies configured it serves everyone (the server logs a warning).
	var none *Proxies
	w := httptest.NewRecorder()
	none.onlyProxies(ok).ServeHTTP(w, req("203.0.113.9:1"))
	if w.Code != 200 {
		t.Errorf("unconfigured = %d", w.Code)
	}
}
