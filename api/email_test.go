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
	test["to"], test["port"] = "ann@example.com", 1
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
