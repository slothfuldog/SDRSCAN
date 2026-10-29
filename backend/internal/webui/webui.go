// Package webui serves the statically generated frontend (nuxt generate) that
// is embedded into the binary, with a fallback page when it was not built.
package webui

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

const fallbackHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>SDRScan</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem">
<h1>SDRScan backend is running</h1>
<p>The web interface has not been built into this binary. Build the frontend
(<code>nuxt generate</code>), copy <code>frontend/.output/public</code> to
<code>backend/internal/webui/dist</code> and rebuild, or point
<code>SDRSCAN_WEB_DIR</code> at the generated directory.</p>
<p>The API is available under <code>/api/v1</code> (health check: <code>/api/v1/healthz</code>).</p>
</body></html>`

var inlineScript = regexp.MustCompile(`(?is)<script(\s[^>]*)?>(.*?)</script>`)

// Handler serves the SPA.
type Handler struct {
	fsys     fs.FS
	index    []byte
	hasIndex bool
	csp      string
}

// New builds a Handler from dir (when non-empty, served from disk) or from the
// embedded files.
func New(dir string) (*Handler, error) {
	h := &Handler{}
	if dir != "" {
		if _, err := os.Stat(dir); err != nil {
			return nil, err
		}
		h.fsys = os.DirFS(dir)
	} else {
		sub, err := fs.Sub(embedded, "dist")
		if err != nil {
			return nil, err
		}
		h.fsys = sub
	}
	if b, err := fs.ReadFile(h.fsys, "index.html"); err == nil {
		h.index, h.hasIndex = b, true
	} else {
		h.index = []byte(fallbackHTML)
	}
	h.csp = buildCSP(h.index)
	return h, nil
}

// HasFrontend reports whether a real index.html is present.
func (h *Handler) HasFrontend() bool { return h.hasIndex }

// CSP returns the Content-Security-Policy for HTML responses.
func (h *Handler) CSP() string { return h.csp }

// buildCSP hashes inline scripts of index.html so Nuxt's runtime config script
// is allowed without 'unsafe-inline'.
func buildCSP(index []byte) string {
	var hashes []string
	for _, m := range inlineScript.FindAllSubmatch(index, -1) {
		attrs := string(m[1])
		if strings.Contains(strings.ToLower(attrs), "src=") {
			continue
		}
		body := m[2]
		if len(bytes.TrimSpace(body)) == 0 {
			continue
		}
		sum := sha256.Sum256(body)
		hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
	}
	script := "script-src 'self'"
	if len(hashes) > 0 {
		script += " " + strings.Join(hashes, " ")
	}
	return "default-src 'none'; " + script + "; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; " +
		"font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
}

// ServeHTTP serves files and falls back to index.html for client-side routes.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := path.Clean("/" + r.URL.Path)
	name := strings.TrimPrefix(p, "/")
	if name != "" && name != "index.html" {
		if f, err := h.fsys.Open(name); err == nil {
			st, serr := f.Stat()
			if serr == nil && st.Mode().IsRegular() {
				defer f.Close()
				if rs, ok := f.(io.ReadSeeker); ok {
					if strings.HasPrefix(name, "_nuxt/") {
						w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					} else {
						w.Header().Set("Cache-Control", "no-cache")
					}
					http.ServeContent(w, r, st.Name(), st.ModTime(), rs)
					return
				}
			}
			f.Close()
		}
		// A missing file with an extension is a real 404 (not a client route).
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(h.index)
	}
}
