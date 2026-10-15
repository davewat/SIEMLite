package api_test

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"siemlite/api"
	"siemlite/pkg/auth"
)

func signIn(e *env, xff, pw string) int {
	e.t.Helper()
	hdr := map[string]string{"Content-Type": "application/json"}
	if xff != "" {
		hdr["X-Forwarded-For"] = xff
	}
	return e.do(e.client(), "POST", "/api/v1/login", `{"username":"root","password":"`+pw+`"}`, hdr).StatusCode
}

// Behind a trusted proxy, each visitor is locked out on their own, and the
// audit log names them, not the proxy.
func TestBehindATrustedProxy(t *testing.T) {
	p, err := api.ParseProxies("127.0.0.1, ::1") // the test client connects from loopback, like Caddy would
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, func(d *api.Deps) { d.Proxies = p })
	e.user("root", auth.RoleAdmin)

	for i := 0; i < 10; i++ {
		if got := signIn(e, "203.0.113.5", "wrong-password-here"); got != 401 {
			t.Fatalf("failure %d = %d", i, got)
		}
	}
	if got := signIn(e, "203.0.113.5", password); got != 429 {
		t.Errorf("the attacker isn't locked out = %d", got)
	}
	// Someone else, through the same proxy, is not affected.
	if got := signIn(e, "198.51.100.7", password); got != 200 {
		t.Errorf("another visitor was locked out too = %d", got)
	}
	// A forged address on the left doesn't get the attacker a fresh allowance.
	if got := signIn(e, "1.2.3.4, 203.0.113.5", password); got != 429 {
		t.Errorf("a forged address escaped the lockout = %d", got)
	}

	// The audit log records the visitor's address.
	root := e.client()
	e.login(root, "root", password)
	deadline := time.Now().Add(3 * time.Second)
	for {
		var out struct {
			Events []struct {
				Message string `json:"message"`
				SrcIP   string `json:"src_ip"`
			} `json:"events"`
		}
		e.call(root, "GET", "/api/v1/search?src_ip=203.0.113.5&limit=50", nil, &out, nil)
		n := 0
		for _, ev := range out.Events {
			if strings.Contains(ev.Message, "Sign-in failed") && ev.SrcIP == "203.0.113.5" {
				n++
			}
		}
		if n >= 10 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit events for the visitor's address: %d of 10", n)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// Without trusted proxies, X-Forwarded-For is ignored: a visitor can't pick
// a new address for each guess.
func TestForwardedForIsIgnoredWithoutAProxy(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	for i := 0; i < 10; i++ {
		signIn(e, "203.0.113."+string(rune('1'+i%9)), "wrong-password-here")
	}
	if got := signIn(e, "198.51.100.200", password); got != 429 {
		t.Errorf("changing X-Forwarded-For escaped the lockout = %d", got)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// The plain-HTTP listener answers the proxy and nobody else.
func TestPlainListener(t *testing.T) {
	for _, tc := range []struct {
		trust string
		want  int
	}{{"127.0.0.1", 200}, {"10.9.9.9", 403}} {
		p, _ := api.ParseProxies(tc.trust)
		e := newEnvWith(t, func(d *api.Deps) { d.Proxies = p })
		srv := api.NewServer("", e.deps)
		addr := freeAddr(t)
		done := make(chan error, 1)
		go func() { done <- srv.StartPlain(addr) }()
		var resp *http.Response
		var err error
		for i := 0; i < 50; i++ {
			if resp, err = http.Get("http://" + addr + "/health"); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("trusting %s: /health over plain HTTP = %d, want %d", tc.trust, resp.StatusCode, tc.want)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
		cancel()
		if err := <-done; err != nil {
			t.Errorf("StartPlain returned %v after shutdown", err)
		}
	}
}
