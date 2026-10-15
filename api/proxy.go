package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Proxies are the reverse proxies (such as Caddy) whose X-Forwarded-For header
// SIEMLite believes. Without them, every request would seem to come from the
// proxy: one person's failed sign-ins would lock everyone out, and the audit
// log would record the proxy's address instead of the visitor's.
//
// Entries are IP addresses, networks (CIDR) or host names. Host names are
// looked up again every 30 seconds, so a proxy container that restarts with a
// new address is still recognised.
type Proxies struct {
	nets  []netip.Prefix
	hosts []string

	lookup func(ctx context.Context, host string) ([]netip.Addr, error)

	mu       sync.RWMutex
	resolved []netip.Addr
}

// ParseProxies reads a comma-separated list of addresses, networks and host names.
func ParseProxies(spec string) (*Proxies, error) {
	p := &Proxies{lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
		case strings.Contains(part, "/"):
			pre, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("%q is not a network such as 172.16.0.0/12", part)
			}
			p.nets = append(p.nets, pre.Masked())
		default:
			if a, err := netip.ParseAddr(part); err == nil {
				p.nets = append(p.nets, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
				continue
			}
			if strings.ContainsAny(part, " /:@") {
				return nil, fmt.Errorf("%q is not an address, network or host name", part)
			}
			p.hosts = append(p.hosts, part)
		}
	}
	return p, nil
}

// Configured reports whether any proxy is trusted.
func (p *Proxies) Configured() bool { return p != nil && (len(p.nets) > 0 || len(p.hosts) > 0) }

// Refresh looks the host names up. A name that doesn't resolve (the proxy
// isn't running yet) is simply not trusted until it does.
func (p *Proxies) Refresh(ctx context.Context) {
	if p == nil || len(p.hosts) == 0 {
		return
	}
	var addrs []netip.Addr
	for _, h := range p.hosts {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		found, err := p.lookup(ctx, h)
		cancel()
		if err != nil {
			continue
		}
		for _, a := range found {
			addrs = append(addrs, a.Unmap())
		}
	}
	p.mu.Lock()
	p.resolved = addrs
	p.mu.Unlock()
}

// Run keeps host names up to date until ctx ends.
func (p *Proxies) Run(ctx context.Context) {
	if p == nil || len(p.hosts) == 0 {
		return
	}
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Refresh(ctx)
		}
	}
}

// Trusted reports whether a is one of the proxies.
func (p *Proxies) Trusted(a netip.Addr) bool {
	if p == nil {
		return false
	}
	a = a.Unmap()
	for _, n := range p.nets {
		if n.Contains(a) {
			return true
		}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, r := range p.resolved {
		if r == a {
			return true
		}
	}
	return false
}

func peerAddr(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// ClientIP is the address of the person making the request. If the connection
// comes from a trusted proxy, X-Forwarded-For is read from the right: each
// proxy appends the address it received from, so the rightmost address that
// isn't itself a trusted proxy is the visitor. Anything further left was
// written by the visitor and can't be believed.
func (p *Proxies) ClientIP(r *http.Request) string {
	peer, ok := peerAddr(r.RemoteAddr)
	if !ok {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		return host
	}
	if !p.Trusted(peer) {
		return peer.String()
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // garbage: stop at the last address that made sense
		}
		client = a.Unmap()
		if !p.Trusted(client) {
			break
		}
	}
	return client.String()
}

// onlyProxies guards the plain-HTTP listener: when proxies are configured, it
// answers only them, so the port is useless to anyone who reaches it directly.
func (p *Proxies) onlyProxies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Configured() {
			if peer, ok := peerAddr(r.RemoteAddr); !ok || !p.Trusted(peer) {
				writeError(w, http.StatusForbidden, "this port only answers the reverse proxy; use the HTTPS address")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
