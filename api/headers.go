package api

import (
	"net/http"
	"strings"

	"siemlite/web"
)

// securityHeaders adds the browser protections every answer carries: no
// content-type sniffing, no framing (the UI can't be put in another site's
// page), no referrer leaking the URL, a Content-Security-Policy that only
// runs the page's own script, and HSTS on the HTTPS listener (behind Caddy,
// Caddy sends it). API answers are never cached by the browser: a search
// result or the user list mustn't survive a sign-out in the browser's cache.
func securityHeaders(next http.Handler) http.Handler {
	csp := web.ContentSecurityPolicy()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", csp)
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
