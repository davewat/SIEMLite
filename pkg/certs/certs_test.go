package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memStore) Setting(_ context.Context, k, def string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[k]; ok {
		return v, nil
	}
	return def, nil
}
func (s *memStore) SetSetting(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}

// writePair writes a self-signed certificate for cn into dir.
func writePair(t *testing.T, dir, cn string) (certFile, keyFile string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return
}

// deadACME is an ACME directory nobody answers at, so issuance always fails.
func deadACME(t *testing.T) Options {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	return Options{DirectoryURL: "http://" + addr + "/directory"}
}

func newManager(t *testing.T, st *memStore, defaults Settings, opts Options) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	cf, kf := writePair(t, dir, "siemlite.local")
	m, err := New(context.Background(), st, cf, kf, filepath.Join(dir, "acme"), defaults, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m, cf
}

func leafCN(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return x.Subject.CommonName
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{"siem.example.com": "siem.example.com", " SIEM.Example.COM. ": "siem.example.com", "xn--bcher-kva.ch": "xn--bcher-kva.ch", "": ""} {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("%q = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"https://siem.example.com", "siem.example.com:443", "siem.example.com/x", "203.0.113.4", "::1",
		"localhost", "siem.localhost", "intranet", "-bad.example.com", "under_score.example.com", "*.example.com", "a..example.com"} {
		var in InputError
		if _, err := NormalizeDomain(bad); !errors.As(err, &in) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}

func TestSelfSignedByDefault(t *testing.T) {
	m, _ := newManager(t, &memStore{m: map[string]string{}}, Settings{}, Options{})
	st := m.Status(context.Background())
	if st.Mode != ModeSelfSigned || st.From != "" || st.SelfSigned.Issuer != "siemlite.local" || !st.SelfSigned.SelfSigned || st.LetsEncrypt != nil {
		t.Fatalf("status = %+v", st)
	}
	for _, name := range []string{"", "siem.example.com", "10.0.0.5"} {
		c, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
		if err != nil || leafCN(t, c) != "siemlite.local" {
			t.Errorf("%q: %v", name, err)
		}
	}
	cfg := m.TLSConfig()
	if cfg.MinVersion != tls.VersionTLS12 || cfg.GetCertificate == nil || !contains(cfg.NextProtos, acme.ALPNProto) {
		t.Errorf("tls config = %+v", cfg)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// Let's Encrypt that can't be reached never locks anyone out: every name,
// the domain included, gets the self-signed certificate, and the page says why.
func TestLetsEncryptFailureFallsBack(t *testing.T) {
	st := &memStore{m: map[string]string{}}
	m, _ := newManager(t, st, Settings{}, deadACME(t))
	ctx := context.Background()
	if err := m.Set(ctx, Settings{Mode: ModeLetsEncrypt, Domain: "SIEM.Example.com"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { s := m.Status(ctx); return !s.Obtaining && s.LastError != "" })
	s := m.Status(ctx)
	if s.Mode != ModeLetsEncrypt || s.Domain != "siem.example.com" || s.From != "system" || s.LetsEncrypt != nil || s.LastTry == 0 {
		t.Errorf("status = %+v", s)
	}
	if !strings.Contains(s.LastError, "Let's Encrypt") {
		t.Errorf("error isn't explained: %s", s.LastError)
	}
	for _, name := range []string{"siem.example.com", "other.example.com", ""} {
		c, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
		if err != nil || leafCN(t, c) != "siemlite.local" {
			t.Errorf("%q didn't fall back: %v", name, err)
		}
	}
	// Switching back clears it.
	if err := m.Set(ctx, Settings{Mode: ModeSelfSigned}); err != nil {
		t.Fatal(err)
	}
	if s := m.Status(ctx); s.Mode != ModeSelfSigned || s.LastError != "" {
		t.Errorf("after switching back = %+v", s)
	}
}

func TestSettingsAreValidatedSavedAndReloaded(t *testing.T) {
	st := &memStore{m: map[string]string{}}
	ctx := context.Background()
	m, _ := newManager(t, st, Settings{}, deadACME(t))
	var in InputError
	for _, bad := range []Settings{{Mode: ModeLetsEncrypt}, {Mode: ModeLetsEncrypt, Domain: "10.0.0.5"}, {Mode: "magic"}} {
		if err := m.Set(ctx, bad); !errors.As(err, &in) {
			t.Errorf("%+v accepted: %v", bad, err)
		}
	}
	if m.Status(ctx).Mode != ModeSelfSigned || st.m[settingKey] != "" {
		t.Error("a refused setting was applied or saved")
	}
	m.Set(ctx, Settings{Mode: ModeLetsEncrypt, Domain: "siem.example.com"})
	// A restart keeps it, and it wins over the flags.
	m2, _ := newManager(t, st, Settings{Mode: ModeSelfSigned}, deadACME(t))
	if s := m2.Status(ctx); s.Mode != ModeLetsEncrypt || s.Domain != "siem.example.com" || s.From != "system" {
		t.Errorf("after restart = %+v", s)
	}
	// Flags apply until something is saved.
	m3, _ := newManager(t, &memStore{m: map[string]string{}}, Settings{Mode: ModeLetsEncrypt, Domain: "flag.example.com"}, deadACME(t))
	if s := m3.Status(ctx); s.Mode != ModeLetsEncrypt || s.Domain != "flag.example.com" || s.From != "setting" {
		t.Errorf("from flags = %+v", s)
	}
	// A bad flag can't stop SIEMLite starting: it runs self-signed.
	m4, _ := newManager(t, &memStore{m: map[string]string{}}, Settings{Mode: ModeLetsEncrypt, Domain: "not a domain"}, Options{})
	if s := m4.Status(ctx); s.Mode != ModeSelfSigned {
		t.Errorf("bad flag = %+v", s)
	}
	// Nor can damaged saved settings.
	m5, _ := newManager(t, &memStore{m: map[string]string{settingKey: "{garbage"}}, Settings{}, Options{})
	if s := m5.Status(ctx); s.Mode != ModeSelfSigned {
		t.Errorf("damaged setting = %+v", s)
	}
}

func TestFilesRenewedOutsideAreReloaded(t *testing.T) {
	st := &memStore{m: map[string]string{}}
	m, certFile := newManager(t, st, Settings{}, Options{})
	dir := filepath.Dir(certFile)
	time.Sleep(10 * time.Millisecond)
	writePair(t, dir, "renewed.local") // same file names
	future := time.Now().Add(time.Minute)
	os.Chtimes(certFile, future, future)
	if err := m.reloadSelf(false); err != nil {
		t.Fatal(err)
	}
	c, _ := m.GetCertificate(&tls.ClientHelloInfo{})
	if leafCN(t, c) != "renewed.local" {
		t.Errorf("served %s after renewal", leafCN(t, c))
	}
	// A broken file is reported and the working certificate kept.
	os.WriteFile(certFile, []byte("garbage"), 0o644)
	later := future.Add(time.Minute)
	os.Chtimes(certFile, later, later)
	if err := m.reloadSelf(false); err == nil {
		t.Error("a broken certificate file was accepted")
	}
	if c, _ := m.GetCertificate(&tls.ClientHelloInfo{}); leafCN(t, c) != "renewed.local" {
		t.Error("the working certificate was dropped")
	}
}

func TestOwns(t *testing.T) {
	m, _ := newManager(t, &memStore{m: map[string]string{}}, Settings{}, Options{})
	c, _ := m.GetCertificate(&tls.ClientHelloInfo{})
	if !m.Owns(context.Background(), c.Certificate[0]) {
		t.Error("doesn't own its own certificate")
	}
	other := writeOther(t)
	if m.Owns(context.Background(), other) {
		t.Error("owns a stranger's certificate")
	}
}

func writeOther(t *testing.T) []byte {
	cf, _ := writePair(t, t.TempDir(), "stranger")
	b, _ := os.ReadFile(cf)
	blk, _ := pem.Decode(b)
	return blk.Bytes
}

func TestExplain(t *testing.T) {
	for raw, want := range map[string]string{
		`acme/autocert: unable to satisfy "https://x/authz/1" for domain "a.example.com": no viable challenge type found`: "port 443",
		`dial tcp 1.2.3.4:443: i/o timeout`:                             "port 443",
		`urn:ietf:params:acme:error:rateLimited: too many certificates`: "rate limit",
		`DNS problem: NXDOMAIN looking up A for a.example.com`:          "DNS",
		`something else entirely`:                                       "didn't issue",
	} {
		if got := explain(errors.New(raw)); !strings.Contains(got, want) {
			t.Errorf("%q -> %q, want it to mention %q", raw, got, want)
		}
	}
}
