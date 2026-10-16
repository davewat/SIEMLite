// Package certs chooses the certificate SIEMLite serves HTTPS (and syslog over
// TLS) with: its own self-signed one (or files supplied with -tls-cert and
// -tls-key), or one from Let's Encrypt for a domain, obtained and renewed
// automatically.
//
// The choice is made on the System page and takes effect at once. With Let's
// Encrypt, only visitors who ask for that domain get its certificate; anyone
// else (an IP address, a LAN name, the health check) still gets the
// self-signed one, and so does the domain until its certificate is obtained.
// So choosing Let's Encrypt on a machine it can't reach never locks anyone out.
package certs

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Modes.
const (
	ModeSelfSigned  = "self-signed"
	ModeLetsEncrypt = "letsencrypt"
)

const settingKey = "tls"

// Settings is the choice made on the System page.
type Settings struct {
	Mode   string `json:"mode"`
	Domain string `json:"domain,omitempty"`
}

// Store is where the choice is kept (storage.Repository).
type Store interface {
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// InputError is a mistake in what a person entered, worded for them.
type InputError string

func (e InputError) Error() string { return string(e) }

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomain checks a domain someone entered and returns it lower-cased.
func NormalizeDomain(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if d == "" {
		return "", nil
	}
	bad := InputError("Enter a domain name only, such as siem.example.com: no https://, port or path.")
	if len(d) > 253 || strings.ContainsAny(d, "/:@ *") {
		return "", bad
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", InputError("Let's Encrypt only issues certificates for names, not IP addresses. Enter a domain name such as siem.example.com.")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 || d == "localhost" || strings.HasSuffix(d, ".localhost") {
		return "", InputError("Enter a full public domain name, such as siem.example.com.")
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", bad
		}
	}
	return d, nil
}

// Options choose the ACME server.
type Options struct {
	DirectoryURL string       // empty: Let's Encrypt
	HTTPClient   *http.Client // nil: the default, trusting the system's CAs
}

// Manager serves the chosen certificate.
type Manager struct {
	// DirectoryURL is the ACME server; empty means Let's Encrypt. HTTPClient
	// talks to it (for an ACME server with a private CA). Set before use.
	DirectoryURL string
	HTTPClient   *http.Client

	store    Store
	certFile string
	keyFile  string
	cacheDir string
	defaults Settings
	log      *slog.Logger

	mu       sync.RWMutex
	settings Settings
	from     string // "system" (this page) or "setting" (flags), or "" for the default
	self     *tls.Certificate
	selfMod  time.Time
	acme     *autocert.Manager
	domain   string // the domain acme is for
	lastErr  string
	lastTry  time.Time
	working  bool // getting a certificate now
}

// New loads the default certificate (certFile/keyFile, which must exist) and
// the saved choice. cacheDir keeps Let's Encrypt's account and certificates.
// defaults come from the flags and apply until something is saved.
func New(ctx context.Context, store Store, certFile, keyFile, cacheDir string, defaults Settings, opts Options, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{store: store, certFile: certFile, keyFile: keyFile, cacheDir: cacheDir, defaults: defaults, log: log,
		DirectoryURL: opts.DirectoryURL, HTTPClient: opts.HTTPClient}
	if err := m.reloadSelf(true); err != nil {
		return nil, err
	}
	s, from := m.load(ctx)
	if err := m.apply(s, from); err != nil {
		// A bad saved or flagged choice must not stop SIEMLite starting.
		log.Error("HTTPS certificate setting ignored; using the self-signed certificate", "err", err)
		_ = m.apply(Settings{Mode: ModeSelfSigned}, "")
	}
	return m, nil
}

func (m *Manager) load(ctx context.Context) (Settings, string) {
	if raw, err := m.store.Setting(ctx, settingKey, ""); err == nil && raw != "" {
		var s Settings
		if json.Unmarshal([]byte(raw), &s) == nil && s.Mode != "" {
			return s, "system"
		}
	}
	if m.defaults.Mode != "" && m.defaults.Mode != ModeSelfSigned {
		return m.defaults, "setting"
	}
	return Settings{Mode: ModeSelfSigned, Domain: m.defaults.Domain}, ""
}

func validate(s Settings) (Settings, error) {
	switch s.Mode {
	case "", ModeSelfSigned:
		s.Mode = ModeSelfSigned
		d, _ := NormalizeDomain(s.Domain) // kept for next time, not used
		s.Domain = d
		return s, nil
	case ModeLetsEncrypt:
		d, err := NormalizeDomain(s.Domain)
		if err != nil {
			return s, err
		}
		if d == "" {
			return s, InputError("Enter the domain to get a Let's Encrypt certificate for, such as siem.example.com.")
		}
		s.Domain = d
		return s, nil
	}
	return s, InputError("Choose self-signed or Let's Encrypt.")
}

// apply switches to s.
func (m *Manager) apply(s Settings, from string) error {
	s, err := validate(s)
	if err != nil {
		return err
	}
	var am *autocert.Manager
	if s.Mode == ModeLetsEncrypt {
		if err := os.MkdirAll(m.cacheDir, 0o700); err != nil {
			return fmt.Errorf("make the certificate folder: %w", err)
		}
		am = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.Domain),
			Cache:      autocert.DirCache(m.cacheDir),
		}
		dir := m.DirectoryURL
		if dir == "" {
			dir = autocert.DefaultACMEDirectory
		}
		am.Client = &acme.Client{DirectoryURL: dir, HTTPClient: acmeHTTPClient(m.HTTPClient)}
	}
	m.mu.Lock()
	m.settings, m.from, m.acme = s, from, am
	m.domain = ""
	if am != nil {
		m.domain = s.Domain
	}
	m.lastErr, m.lastTry = "", time.Time{}
	m.mu.Unlock()
	if am != nil {
		go m.obtain(s.Domain)
	}
	return nil
}

// Set saves a new choice and switches to it.
func (m *Manager) Set(ctx context.Context, s Settings) error {
	s, err := validate(s)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(s)
	if err := m.store.SetSetting(ctx, settingKey, string(b)); err != nil {
		return err
	}
	return m.apply(s, "system")
}

// hello is what a browser would send for domain, so autocert issues the same
// (ECDSA) certificate a visitor would get.
func hello(domain string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        domain,
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	}
}

// obtain gets (or loads) the domain's certificate now, rather than on the
// first visit, so the System page can say whether it worked.
func (m *Manager) obtain(domain string) {
	m.mu.Lock()
	am := m.acme
	if am == nil || m.domain != domain || m.working {
		m.mu.Unlock()
		return
	}
	m.working, m.lastTry = true, time.Now()
	m.mu.Unlock()
	_, err := am.GetCertificate(hello(domain))
	m.mu.Lock()
	defer m.mu.Unlock()
	m.working = false
	if m.domain != domain {
		return // switched away meanwhile
	}
	if err != nil {
		m.lastErr = explain(err)
		m.log.Warn("Let's Encrypt certificate not obtained", "domain", domain, "err", err)
		return
	}
	m.lastErr = ""
	m.log.Info("Let's Encrypt certificate ready", "domain", domain)
}

// explain turns an ACME failure into something a person can act on.
func explain(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "rateLimited") || strings.Contains(s, "too many"):
		return "Let's Encrypt's rate limit was reached for this name. Wait (usually an hour, up to a week) and it will try again."
	case strings.Contains(strings.ToLower(s), "dns problem") || strings.Contains(s, "NXDOMAIN") || strings.Contains(s, "no valid A records"):
		return "Let's Encrypt couldn't find the name in DNS. Point an A or AAAA record for it at this server's public address."
	case strings.Contains(s, "unable to satisfy") || strings.Contains(s, "no viable challenge") ||
		strings.Contains(s, "connection") || strings.Contains(s, "Timeout") || strings.Contains(s, "timeout") || strings.Contains(s, "unauthorized"):
		return "Let's Encrypt couldn't confirm that this server answers for the name on port 443. Make sure the name points at this server and port 443 is open to the internet and forwarded to SIEMLite, then save again. Check this address can help."
	}
	return "Let's Encrypt didn't issue a certificate: " + trim(s)
}

func trim(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func isChallenge(h *tls.ClientHelloInfo) bool {
	return len(h.SupportedProtos) == 1 && h.SupportedProtos[0] == acme.ALPNProto
}

// GetCertificate picks the certificate for one TLS connection.
func (m *Manager) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	am, domain, self := m.acme, m.domain, m.self
	m.mu.RUnlock()
	if am != nil {
		if isChallenge(h) {
			return am.GetCertificate(h) // Let's Encrypt checking that this server answers for the name
		}
		if strings.TrimSuffix(strings.ToLower(h.ServerName), ".") == domain {
			c, err := am.GetCertificate(h)
			if err == nil {
				return c, nil
			}
			m.mu.Lock()
			if m.domain == domain {
				m.lastErr, m.lastTry = explain(err), time.Now()
			}
			m.mu.Unlock()
		}
	}
	return self, nil
}

// TLSConfig is the configuration for the HTTPS server and syslog over TLS.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
		// acme-tls/1 lets Let's Encrypt check this server on port 443.
		NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
	}
}

// --- Status ---

// CertInfo describes a certificate.
type CertInfo struct {
	Names      []string `json:"names"`
	Issuer     string   `json:"issuer"`
	NotAfter   int64    `json:"not_after"` // unix milliseconds
	SelfSigned bool     `json:"self_signed"`
}

// Status is what the System page shows.
type Status struct {
	Settings
	// From is where the choice comes from: "system" (this page), "setting"
	// (flags or .env), or empty for the default.
	From string `json:"from,omitempty"`
	// SelfSigned is the certificate served to everyone else.
	SelfSigned CertInfo `json:"self_signed_certificate"`
	// LetsEncrypt is the domain's certificate, once there is one.
	LetsEncrypt *CertInfo `json:"letsencrypt_certificate,omitempty"`
	Obtaining   bool      `json:"obtaining,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	LastTry     int64     `json:"last_try,omitempty"`
}

func info(der []byte) CertInfo {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return CertInfo{}
	}
	names := append([]string(nil), c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	issuer := c.Issuer.CommonName
	if issuer == "" && len(c.Issuer.Organization) > 0 {
		issuer = c.Issuer.Organization[0]
	}
	// Self-signed: it names itself as issuer and its own key signed it (a CA
	// flag isn't required, so supplied self-signed certificates count too).
	self := bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
	return CertInfo{Names: names, Issuer: issuer, NotAfter: c.NotAfter.UnixMilli(), SelfSigned: self}
}

// Status reports the choice and the certificates.
func (m *Manager) Status(ctx context.Context) Status {
	m.mu.RLock()
	st := Status{Settings: m.settings, From: m.from, Obtaining: m.working, LastError: m.lastErr}
	if !m.lastTry.IsZero() {
		st.LastTry = m.lastTry.UnixMilli()
	}
	if m.self != nil && len(m.self.Certificate) > 0 {
		st.SelfSigned = info(m.self.Certificate[0])
	}
	am, domain := m.acme, m.domain
	m.mu.RUnlock()
	if am != nil {
		// autocert keeps the key and chain in its cache under the domain name.
		if data, err := am.Cache.Get(ctx, domain); err == nil {
			for rest := data; ; {
				var b *pem.Block
				if b, rest = pem.Decode(rest); b == nil {
					break
				}
				if b.Type == "CERTIFICATE" {
					ci := info(b.Bytes)
					st.LetsEncrypt = &ci
					break
				}
			}
		}
	}
	return st
}

// Owns reports whether a certificate (DER) is one this server serves: the
// self-signed one or the domain's Let's Encrypt one. The reachability check
// uses it to be sure it reached this server, not something in between.
func (m *Manager) Owns(ctx context.Context, der []byte) bool {
	m.mu.RLock()
	self, am, domain := m.self, m.acme, m.domain
	m.mu.RUnlock()
	if self != nil && len(self.Certificate) > 0 && bytes.Equal(self.Certificate[0], der) {
		return true
	}
	if am == nil {
		return false
	}
	data, err := am.Cache.Get(ctx, domain)
	if err != nil {
		return false
	}
	for rest := data; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return false
		}
		if b.Type == "CERTIFICATE" {
			return bytes.Equal(b.Bytes, der)
		}
	}
}

// --- The default certificate files ---

func (m *Manager) reloadSelf(first bool) error {
	fi, err := os.Stat(m.certFile)
	if err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	m.mu.RLock()
	same := !first && fi.ModTime().Equal(m.selfMod)
	m.mu.RUnlock()
	if same {
		return nil
	}
	pair, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	m.mu.Lock()
	m.self, m.selfMod = &pair, fi.ModTime()
	m.mu.Unlock()
	if !first {
		m.log.Info("reloaded the TLS certificate files", "cert", m.certFile)
	}
	return nil
}

// Run reloads the certificate files when they change (a certificate renewed
// outside SIEMLite takes effect without a restart) until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.reloadSelf(false); err != nil {
				m.log.Warn("couldn't reload the TLS certificate files; keeping the current ones", "err", err)
			}
		}
	}
}
