package api_test

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"siemlite/pkg/auth"
)

// smtpSink is a minimal SMTP server that keeps what it is sent.
type smtpSink struct {
	mu   sync.Mutex
	data string
	user string
}

func newSMTPSink(t *testing.T) (*smtpSink, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &smtpSink{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				rd := bufio.NewReader(c)
				say := func(x string) { io.WriteString(c, x+"\r\n") }
				say("220 sink")
				for {
					l, err := rd.ReadString('\n')
					if err != nil {
						return
					}
					up := strings.ToUpper(strings.TrimSpace(l))
					switch {
					case strings.HasPrefix(up, "EHLO"):
						say("250-sink\r\n250 AUTH PLAIN")
					case strings.HasPrefix(up, "DATA"):
						say("354 go")
						var b strings.Builder
						for {
							d, _ := rd.ReadString('\n')
							if strings.TrimRight(d, "\r\n") == "." {
								break
							}
							b.WriteString(d)
						}
						s.mu.Lock()
						s.data = b.String()
						s.mu.Unlock()
						say("250 queued")
					case strings.HasPrefix(up, "QUIT"):
						say("221 bye")
						return
					default:
						say("250 ok")
					}
				}
			}()
		}
	}()
	return s, ln.Addr().(*net.TCPAddr).Port
}

func TestEmailSettingsAPI(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	sink, port := newSMTPSink(t)

	var v map[string]any
	if got := e.call(root, "GET", "/api/v1/system/email", nil, &v, nil); got != 200 || v["configured"] != false || v["port"] != float64(587) {
		t.Fatalf("empty = %d %v", got, v)
	}

	form := map[string]any{"host": "127.0.0.1", "port": port, "security": "none", "username": "", "from_address": "siem@example.com", "from_name": "SIEMLite"}

	// Mistakes are explained, not saved.
	for name, mod := range map[string]func(map[string]any){
		"no host":   func(m map[string]any) { m["host"] = "smtp://x" },
		"bad port":  func(m map[string]any) { m["port"] = 0 },
		"bad from":  func(m map[string]any) { m["from_address"] = "nope" },
		"security":  func(m map[string]any) { m["security"] = "ssl" },
		"long pass": func(m map[string]any) { m["password"] = strings.Repeat("x", 600) },
	} {
		bad := map[string]any{}
		for k, x := range form {
			bad[k] = x
		}
		mod(bad)
		var er map[string]string
		if got := e.call(root, "PUT", "/api/v1/system/email", bad, &er, nil); got != 400 || er["error"] == "" {
			t.Errorf("%s = %d %v", name, got, er)
		}
	}
	if got := e.call(root, "GET", "/api/v1/system/email", nil, &v, nil); got != 200 || v["configured"] != false {
		t.Errorf("a refused save changed the settings: %v", v)
	}

	// Save with a password; it never comes back.
	form["password"] = "s3cret-pass-word"
	var body strings.Builder
	if got := e.call(root, "PUT", "/api/v1/system/email", form, &v, nil); got != 200 || v["configured"] != true || v["has_password"] != true {
		t.Fatalf("save = %d %v", got, v)
	}
	body.WriteString(strings.Join(keys(v), ","))
	if _, leaked := v["password"]; leaked || strings.Contains(body.String(), "s3cret") {
		t.Errorf("the password came back: %v", v)
	}
	var again map[string]any
	e.call(root, "GET", "/api/v1/system/email", nil, &again, nil)
	if _, leaked := again["password"]; leaked || again["from_name"] != "SIEMLite" || again["has_password"] != true {
		t.Errorf("GET = %v", again)
	}

	// Pointing the saved settings at another server needs the password typed again.
	moved := map[string]any{"host": "localhost", "port": port, "security": "none", "from_address": "siem@example.com"}
	var mv map[string]string
	if got := e.call(root, "PUT", "/api/v1/system/email", moved, &mv, nil); got != 400 || !strings.Contains(mv["error"], "enter the password again") {
		t.Errorf("save with another host and no password = %d %v", got, mv)
	}

	// A test email goes through the form's settings.
	test := map[string]any{"host": "127.0.0.1", "port": port, "security": "none", "from_address": "siem@example.com", "to": "ann@example.com"}
	if got := e.call(root, "POST", "/api/v1/system/email/test", test, nil, nil); got != 200 {
		t.Fatalf("test email = %d", got)
	}
	sink.mu.Lock()
	got := sink.data
	sink.mu.Unlock()
	if !strings.Contains(got, "Subject: SIEMLite test email") || !strings.Contains(got, "To: <ann@example.com>") {
		t.Errorf("test email:\n%s", got)
	}
	// A bad recipient is the person's mistake; a dead server is a failed send.
	test["to"] = "not an address"
	var er map[string]string
	if got := e.call(root, "POST", "/api/v1/system/email/test", test, &er, nil); got != 400 {
		t.Errorf("bad recipient = %d %v", got, er)
	}
	// The saved password is only used with the server it was saved for: aiming a test at
	// another port needs a password of its own, so it can't be sent somewhere else.
	test["to"], test["port"] = "ann@example.com", 1
	if got := e.call(root, "POST", "/api/v1/system/email/test", test, &er, nil); got != 400 || !strings.Contains(er["error"], "enter its password") {
		t.Errorf("saved password reused for another server = %d %v", got, er)
	}
	test["password"] = "typed-for-this-server"
	if got := e.call(root, "POST", "/api/v1/system/email/test", test, &er, nil); got != 502 || !strings.Contains(er["error"], "connect") {
		t.Errorf("dead server = %d %v", got, er)
	}

	// An empty host clears it.
	if got := e.call(root, "PUT", "/api/v1/system/email", map[string]any{"host": ""}, &v, nil); got != 200 || v["configured"] != false || v["has_password"] != false {
		t.Errorf("clear = %d %v", got, v)
	}
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestIntegrationsAPI(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	_, port := newSMTPSink(t)

	type card struct {
		ID, Name, Description, State, Summary string
		Configured, Enabled                   bool
	}
	var list struct{ Integrations []card }
	// The integrations are listed by name, so find email by id.
	emailCard := func(cards []card) card {
		for _, c := range cards {
			if c.ID == "email" {
				return c
			}
		}
		return card{}
	}
	if got := e.call(root, "GET", "/api/v1/integrations", nil, &list, nil); got != 200 || len(list.Integrations) != 2 {
		t.Fatalf("list = %d %+v", got, list)
	}
	if c := emailCard(list.Integrations); c.ID != "email" || c.Name != "Email" || c.State != "needs_setup" || c.Description == "" {
		t.Errorf("email card = %+v", c)
	}

	// Nothing to turn on yet.
	var er map[string]string
	if got := e.call(root, "POST", "/api/v1/integrations/email/enabled", map[string]any{"enabled": true}, &er, nil); got != 400 || er["error"] == "" {
		t.Errorf("enable with nothing saved = %d %v", got, er)
	}
	if got := e.call(root, "POST", "/api/v1/integrations/nope/enabled", map[string]any{"enabled": true}, nil, nil); got != 404 {
		t.Errorf("unknown integration = %d", got)
	}
	if got := e.call(root, "POST", "/api/v1/integrations/email/enabled", map[string]any{}, &er, nil); got != 400 {
		t.Errorf("no enabled field = %d", got)
	}

	// Save through the new path; the old path still reaches the same settings.
	form := map[string]any{"host": "127.0.0.1", "port": port, "security": "none", "from_address": "siem@example.com", "from_name": "SIEMLite", "password": "pw"}
	var v map[string]any
	if got := e.call(root, "PUT", "/api/v1/integrations/email", form, &v, nil); got != 200 || v["configured"] != true || v["enabled"] != true {
		t.Fatalf("save = %d %v", got, v)
	}
	var old map[string]any
	if got := e.call(root, "GET", "/api/v1/system/email", nil, &old, nil); got != 200 || old["host"] != "127.0.0.1" || old["has_password"] != true {
		t.Errorf("old path = %d %v", got, old)
	}
	if _, leaked := old["password"]; leaked {
		t.Error("the password came back")
	}
	e.call(root, "GET", "/api/v1/integrations", nil, &list, nil)
	if c := emailCard(list.Integrations); c.State != "on" || !strings.Contains(c.Summary, "127.0.0.1") {
		t.Errorf("on card = %+v", c)
	}

	// Off keeps the settings; saving other changes while off keeps it off.
	var one card
	if got := e.call(root, "POST", "/api/v1/integrations/email/enabled", map[string]any{"enabled": false}, &one, nil); got != 200 || one.State != "off" || !one.Configured || one.Enabled {
		t.Fatalf("turn off = %d %+v", got, one)
	}
	form["from_name"], form["password"] = "Renamed", nil
	delete(form, "password")
	if got := e.call(root, "PUT", "/api/v1/integrations/email", form, &v, nil); got != 200 || v["enabled"] != false || v["from_name"] != "Renamed" || v["has_password"] != true {
		t.Errorf("save while off = %d %v", got, v)
	}
	if got := e.call(root, "POST", "/api/v1/integrations/email/enabled", map[string]any{"enabled": true}, &one, nil); got != 200 || one.State != "on" {
		t.Errorf("turn on = %d %+v", got, one)
	}

	// Removing the settings returns it to needing setup.
	if got := e.call(root, "PUT", "/api/v1/integrations/email", map[string]any{"host": ""}, &v, nil); got != 200 {
		t.Fatalf("clear = %d", got)
	}
	e.call(root, "GET", "/api/v1/integrations", nil, &list, nil)
	if c := emailCard(list.Integrations); c.State != "needs_setup" {
		t.Errorf("after clear = %+v", c)
	}
}
