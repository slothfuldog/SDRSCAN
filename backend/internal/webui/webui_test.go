package webui

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFallbackWhenFrontendIsMissing(t *testing.T) {
	h, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if h.HasFrontend() {
		t.Skip("a real frontend is embedded in this build")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/anything/deep", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "SDRScan backend is running") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(h.CSP(), "default-src 'none'") {
		t.Fatal(h.CSP())
	}
}

func TestServesFilesSPAFallbackAndInlineScriptHash(t *testing.T) {
	dir := t.TempDir()
	inline := `window.__NUXT__={config:{}}`
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte(`<html><head><script src="/_nuxt/a.js"></script><script>`+inline+`</script></head><body>app</body></html>`), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "_nuxt"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "_nuxt", "a.js"), []byte("console.log(1)"), 0o644)
	h, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	get := func(p string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", p, nil))
		return rr
	}
	if rr := get("/_nuxt/a.js"); rr.Code != 200 || rr.Body.String() != "console.log(1)" || !strings.Contains(rr.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %v", rr.Code, rr.Header())
	}
	if rr := get("/projects/7"); rr.Code != 200 || !strings.Contains(rr.Body.String(), "app") {
		t.Fatalf("SPA route: %d", rr.Code)
	}
	if rr := get("/missing.js"); rr.Code != 404 {
		t.Fatalf("missing asset must be 404: %d", rr.Code)
	}
	if rr := get("/../../etc/passwd"); rr.Code == 200 && strings.Contains(rr.Body.String(), "root:") {
		t.Fatal("path traversal")
	}
	sum := sha256.Sum256([]byte(inline))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(h.CSP(), want) || strings.Contains(h.CSP(), "unsafe-inline'") && strings.Contains(h.CSP(), "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("CSP: %s", h.CSP())
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/", nil))
	if rr.Code != 405 {
		t.Fatalf("POST: %d", rr.Code)
	}
}
