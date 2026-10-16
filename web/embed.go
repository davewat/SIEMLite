// Package web embeds the single-page frontend.
package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"io/fs"
	"net/http"
	"strings"
	"sync"
)

//go:embed static
var assets embed.FS

// Handler serves the frontend from the embedded static directory. Folders
// are never listed: only files are served.
func Handler() http.Handler {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err) // static dir is embedded at build time
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

var (
	cspOnce sync.Once
	csp     string
)

// ContentSecurityPolicy is the Content-Security-Policy for the UI. The page
// has two inline scripts, so their SHA-256 hashes are computed from the
// embedded page once, at first use: the policy stays right when the page
// changes, and nothing else may run inline. Styles allow inline values
// because the page sets a few style attributes; that can't run script.
func ContentSecurityPolicy() string {
	cspOnce.Do(func() {
		page, err := assets.ReadFile("static/index.html")
		if err != nil {
			panic(err)
		}
		scripts := "'self'"
		for _, body := range inlineScripts(page) {
			sum := sha256.Sum256(body)
			scripts += " 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		}
		csp = strings.Join([]string{
			"default-src 'self'",
			"script-src " + scripts,
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data:",
			"font-src 'self'",
			"connect-src 'self'",
			"frame-ancestors 'none'",
			"base-uri 'none'",
			"form-action 'self'",
			"object-src 'none'",
		}, "; ")
	})
	return csp
}

// inlineScripts returns the bodies of every <script>...</script> in page, as
// the browser hashes them: the exact bytes between the tags.
func inlineScripts(page []byte) [][]byte {
	var out [][]byte
	open, close := []byte("<script>"), []byte("</script>")
	for {
		i := bytes.Index(page, open)
		if i < 0 {
			return out
		}
		page = page[i+len(open):]
		j := bytes.Index(page, close)
		if j < 0 {
			return out
		}
		out = append(out, page[:j])
		page = page[j+len(close):]
	}
}
