package api

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/certs"
)

// The System page's HTTPS certificate section: self-signed, or Let's Encrypt
// for a domain (see pkg/certs).

type tlsView struct {
	certs.Status
	Resolves   []string `json:"resolves_to,omitempty"`
	ResolveErr string   `json:"resolve_error,omitempty"`
}

func (s *Server) tlsState(ctx context.Context) tlsView {
	v := tlsView{Status: s.deps.Certs.Status(ctx)}
	if v.Domain != "" {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if addrs, err := net.DefaultResolver.LookupHost(ctx, v.Domain); err != nil {
			v.ResolveErr = "The name doesn't resolve yet. Point its DNS (an A or AAAA record) at this server's public address."
		} else {
			v.Resolves = addrs
		}
	}
	return v
}

func (s *Server) certsReady(w http.ResponseWriter) bool {
	if s.deps.Certs == nil {
		writeError(w, http.StatusNotImplemented, "this server can't change its certificate")
		return false
	}
	return true
}

func (s *Server) handleGetTLS(w http.ResponseWriter, r *http.Request) {
	if !s.certsReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.tlsState(r.Context()))
}

func (s *Server) handleSaveTLS(w http.ResponseWriter, r *http.Request) {
	if !s.certsReady(w) {
		return
	}
	var req certs.Settings
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	if err := s.deps.Certs.Set(r.Context(), req); err != nil {
		var bad certs.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.internal(w, "save the certificate setting", err)
		return
	}
	who := auth.FromContext(r.Context()).Name
	v := s.tlsState(r.Context())
	msg := who + " switched HTTPS to the self-signed certificate"
	if v.Mode == certs.ModeLetsEncrypt {
		msg = who + " switched HTTPS to a Let's Encrypt certificate for " + v.Domain
	}
	s.deps.Logger.Info("HTTPS certificate setting changed", "mode", v.Mode, "domain", v.Domain, "by", who)
	s.audit(r, audit.Entry{Action: "system.tls", Severity: 3, Message: msg, Fields: map[string]string{"target": v.Domain}})
	writeJSON(w, http.StatusOK, v)
}

// handleCheckTLS checks that a domain reaches this SIEMLite on port 443, the
// way Let's Encrypt will: it asks the domain for a one-time token that only
// this server knows.
func (s *Server) handleCheckTLS(w http.ResponseWriter, r *http.Request) {
	if !s.certsReady(w) {
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	d, err := certs.NormalizeDomain(req.Domain)
	if err == nil && d == "" {
		err = errors.New("Enter the domain to check.")
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		s.internal(w, "make a check token", err)
		return
	}
	nonce := hex.EncodeToString(b)
	s.checkMu.Lock()
	if s.checks == nil {
		s.checks = map[string]time.Time{}
	}
	for k, exp := range s.checks {
		if time.Now().After(exp) {
			delete(s.checks, k)
		}
	}
	s.checks[nonce] = time.Now().Add(30 * time.Second)
	s.checkMu.Unlock()
	defer func() { s.checkMu.Lock(); delete(s.checks, nonce); s.checkMu.Unlock() }()

	// Before Let's Encrypt has issued the certificate this server presents its
	// self-signed one, which no CA vouches for, so the usual verification is
	// replaced by a stricter one: the server must present one of SIEMLite's
	// own certificates. Only the random token is sent; no credentials.
	ctx := r.Context()
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // pinned to our own certificate in VerifyConnection
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 || !s.deps.Certs.Owns(ctx, cs.PeerCertificates[0].Raw) {
					return errNotOurs
				}
				return nil
			},
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get("https://" + d + "/.well-known/siemlite-check/" + nonce)
	out := map[string]any{"domain": d, "reachable": false}
	switch {
	case errors.Is(err, errNotOurs):
		out["detail"] = "https://" + d + " answered with another server's certificate: the name or port 443 leads somewhere else (another server, or a proxy in the way)."
	case err != nil:
		out["detail"] = "Couldn't connect to https://" + d + " (port 443): " + shortNetErr(err) +
			". Let's Encrypt needs port 443 open to the internet and forwarded to SIEMLite. If this server can't reach its own public address (some routers don't allow it), the check can fail even when the outside world can connect."
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == nonce {
			out["reachable"] = true
			out["detail"] = "https://" + d + " on port 443 reaches this SIEMLite."
		} else {
			out["detail"] = "https://" + d + " answered, but it isn't this SIEMLite (another server, or a proxy in the way)."
		}
	}
	writeJSON(w, http.StatusOK, out)
}

var errNotOurs = errors.New("not this server's certificate")

func shortNetErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}

// handleCheckEcho answers a reachability check with its token, if it is one
// this server is running. It is public: the token is random and short-lived.
func (s *Server) handleCheckEcho(w http.ResponseWriter, r *http.Request) {
	nonce := r.PathValue("nonce")
	s.checkMu.Lock()
	exp, ok := s.checks[nonce]
	s.checkMu.Unlock()
	if !ok || time.Now().After(exp) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, nonce)
}
