package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
)

// The public web address: the domain Caddy serves SIEMLite on (see
// compose.public.yaml). It is chosen on the System page. Caddy asks SIEMLite
// whether it may get a certificate for a name before it does (on-demand TLS),
// and SIEMLite says yes only for this one, so changing it needs no restart.

const publicHostKey = "public_host"

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// errBadDomain explains what a domain must look like.
var errBadDomain = errors.New("Enter a domain name only, such as siem.example.com: no https://, port or path.")

// normalizeDomain checks a domain someone entered and returns it lower-cased.
func normalizeDomain(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if d == "" {
		return "", nil
	}
	if len(d) > 253 || strings.ContainsAny(d, "/:@ *") {
		return "", errBadDomain
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", errors.New("Let's Encrypt only issues certificates for names, not IP addresses. Enter a domain name such as siem.example.com.")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 || d == "localhost" || strings.HasSuffix(d, ".localhost") {
		return "", errors.New("Enter a full public domain name, such as siem.example.com.")
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", errBadDomain
		}
	}
	return d, nil
}

// publicDomain is the domain in use: the one saved on the System page, or
// else the -domain flag (SIEMLITE_DOMAIN in .env).
func (s *Server) publicDomain(ctx context.Context) (domain, from string) {
	if v := s.savedDomain(ctx); v != "" {
		return v, "system"
	}
	if d, err := normalizeDomain(s.deps.Domain); err == nil && d != "" {
		return d, "setting"
	}
	return "", ""
}

// savedDomain is the domain saved on the System page, kept in memory because
// every request through Caddy checks it.
func (s *Server) savedDomain(ctx context.Context) string {
	s.domainMu.Lock()
	defer s.domainMu.Unlock()
	if !s.domainLoaded {
		v, err := s.deps.Repo.Setting(ctx, publicHostKey, "")
		if err != nil {
			return "" // try again next time
		}
		s.domain, s.domainLoaded = v, true
	}
	return s.domain
}

type publicView struct {
	Domain string `json:"domain"`
	// From is where the domain comes from: "system" (this page) or
	// "setting" (SIEMLITE_DOMAIN), or empty.
	From string `json:"from,omitempty"`
	// BehindCaddy is whether SIEMLite is running behind a reverse proxy
	// (compose.public.yaml), so the domain is in effect.
	BehindCaddy bool     `json:"behind_caddy"`
	Resolves    []string `json:"resolves_to,omitempty"`
	ResolveErr  string   `json:"resolve_error,omitempty"`
}

func (s *Server) publicState(ctx context.Context) publicView {
	d, from := s.publicDomain(ctx)
	v := publicView{Domain: d, From: from, BehindCaddy: s.deps.BehindProxy}
	if d != "" {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupHost(ctx, d)
		if err != nil {
			v.ResolveErr = "The name doesn't resolve yet. Point its DNS (an A or AAAA record) at this server."
		} else {
			v.Resolves = addrs
		}
	}
	return v
}

func (s *Server) handleGetPublic(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.publicState(r.Context()))
}

func (s *Server) handleSavePublic(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	d, err := normalizeDomain(req.Domain)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.domainMu.Lock()
	err = s.deps.Repo.SetSetting(r.Context(), publicHostKey, d)
	if err == nil {
		s.domain, s.domainLoaded = d, true
	}
	s.domainMu.Unlock()
	if err != nil {
		s.internal(w, "save the web address", err)
		return
	}
	who := auth.FromContext(r.Context()).Name
	msg := who + " removed the public web address"
	if d != "" {
		msg = who + " set the public web address to https://" + d
	}
	s.deps.Logger.Info("public web address changed", "domain", d, "by", who)
	s.audit(r, audit.Entry{Action: "system.domain", Severity: 3, Message: msg, Fields: map[string]string{"target": d}})
	writeJSON(w, http.StatusOK, s.publicState(r.Context()))
}

// handleCaddyAsk answers Caddy's question before it gets a certificate: is
// this the domain SIEMLite is served on? Only Caddy may ask, directly (not a
// visitor's request passed through it).
func (s *Server) handleCaddyAsk(w http.ResponseWriter, r *http.Request) {
	peer, ok := peerAddr(r.RemoteAddr)
	if !ok || !s.deps.Proxies.Trusted(peer) || r.Header.Get("X-Forwarded-For") != "" {
		writeError(w, http.StatusForbidden, "only the reverse proxy may ask")
		return
	}
	want, _ := s.publicDomain(r.Context())
	got, err := normalizeDomain(r.URL.Query().Get("domain"))
	if want == "" || err != nil || got != want {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// publicHostGuard sends visitors who reach SIEMLite through the proxy by any
// other name to the public domain. Caddy keeps serving a name it already has
// a certificate for, so without this an old domain would keep working after
// the address is changed.
func (s *Server) publicHostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") != "" {
			if peer, ok := peerAddr(r.RemoteAddr); ok && s.deps.Proxies.Trusted(peer) {
				if want, _ := s.publicDomain(r.Context()); want != "" {
					host := strings.ToLower(r.Host)
					if h, _, err := net.SplitHostPort(host); err == nil {
						host = h
					}
					if host != want {
						http.Redirect(w, r, "https://"+want+r.URL.RequestURI(), http.StatusPermanentRedirect)
						return
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
