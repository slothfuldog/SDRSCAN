package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sdrscan/sdrscan/backend/internal/auth"
	"github.com/sdrscan/sdrscan/backend/internal/crypt"
	"github.com/sdrscan/sdrscan/backend/internal/httpapi"
	"github.com/sdrscan/sdrscan/backend/internal/ingest"
	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/vulndb"
	"github.com/sdrscan/sdrscan/backend/internal/webui"
)

// Password is the password of every user made by CreateUser.
const Password = "correct-horse-battery"

var (
	hashOnce sync.Once
	pwHash   string
)

func passwordHash() string {
	hashOnce.Do(func() { pwHash, _ = auth.NewHasher().Hash(Password) })
	return pwHash
}

// Env is a complete backend (database, API server, runner) for one test.
type Env struct {
	T      testing.TB
	Pool   *pgxpool.Pool
	DBURL  string
	Store  *store.Store
	Ingest *ingest.Ingester
	Guard  *netguard.Guard
	Box    *crypt.Box
	API    *httpapi.Server
	HTTP   *httptest.Server
	Runner *scanner.Runner
	Opt    httpapi.Options
	VulnDB *vulndb.Manager
}

// EnvOptions tweak the environment.
type EnvOptions struct {
	Guard  *netguard.Guard
	Runner scanner.Config
	Server httpapi.Options
	Ingest ingest.Config
	NoKey  bool
	// VulnDB configures the vulnerability database manager (zero = feature not configured).
	VulnDB vulndb.Config
}

// NewEnv builds an Env backed by a fresh database.
func NewEnv(t testing.TB, eo EnvOptions) *Env {
	t.Helper()
	pool, url := NewDBWithURL(t)
	st := store.New(pool)
	key := bytes.Repeat([]byte{7}, 32)
	if eo.NoKey {
		key = nil
	}
	box, err := crypt.New(key)
	if err != nil {
		t.Fatal(err)
	}
	guard := eo.Guard
	if guard == nil {
		guard = &netguard.Guard{Resolver: DefaultResolver()}
	}
	ing := ingest.New(st, eo.Ingest)
	web, err := webui.New("")
	if err != nil {
		t.Fatal(err)
	}
	opt := eo.Server
	opt.CookieSecure = false
	opt.Version = "test"
	if opt.AllowedHosts == nil {
		opt.AllowedHosts = []string{"127.0.0.1", "localhost"}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	api := httpapi.New(st, ing, box, guard, web, log, opt)
	vctx, vcancel := context.WithCancel(context.Background())
	vdb := vulndb.New(vctx, eo.VulnDB, st, log)
	api.VulnDB = vdb
	t.Cleanup(func() { vcancel(); vdb.Wait() })
	srv := httptest.NewServer(api.Router())
	t.Cleanup(srv.Close)
	rc := eo.Runner
	if rc.Workdir == "" {
		rc.Workdir = t.TempDir()
	}
	if guard.AllowLoopback {
		rc.DastAllowPrivate = true
	}
	run := scanner.New(st, ing, guard, box, rc, log)
	api.LoginTester = run
	return &Env{T: t, Pool: pool, DBURL: url, Store: st, Ingest: ing, Guard: guard, Box: box, API: api, HTTP: srv, Runner: run, Opt: opt, VulnDB: vdb}
}

// CreateUser inserts a user directly (password: Password).
func (e *Env) CreateUser(username, role string, canDAST bool) store.User {
	e.T.Helper()
	u, err := e.Store.CreateUser(context.Background(), username, passwordHash(), role, canDAST, false)
	if err != nil {
		e.T.Fatalf("create user: %v", err)
	}
	return u
}

// Client is an authenticated HTTP client (cookie + CSRF).
type Client struct {
	Env    *Env
	Cookie string
	CSRF   string
	User   store.User
}

// Login creates a session for u directly in the database.
func (e *Env) Login(u store.User) *Client {
	e.T.Helper()
	tok, csrf := auth.NewToken(32), auth.NewHexToken(32)
	if err := e.Store.CreateSession(context.Background(), u.ID, auth.HashToken(tok), csrf, 24*time.Hour); err != nil {
		e.T.Fatal(err)
	}
	return &Client{Env: e, Cookie: tok, CSRF: csrf, User: u}
}

// Anonymous returns a client without a session.
func (e *Env) Anonymous() *Client { return &Client{Env: e} }

// Resp is a decoded response.
type Resp struct {
	Status int
	Header http.Header
	Body   []byte
}

// JSON decodes the body into a generic map.
func (r Resp) JSON() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.Body, &m)
	return m
}

// ErrCode returns error.code of an error body.
func (r Resp) ErrCode() string {
	if e, ok := r.JSON()["error"].(map[string]any); ok {
		s, _ := e["code"].(string)
		return s
	}
	return ""
}

// ErrDetails returns error.details of an error body (nil when absent).
func (r Resp) ErrDetails() map[string]any {
	if e, ok := r.JSON()["error"].(map[string]any); ok {
		d, _ := e["details"].(map[string]any)
		return d
	}
	return nil
}

// ErrField returns error.details.field.
func (r Resp) ErrField() string {
	f, _ := r.ErrDetails()["field"].(string)
	return f
}

// ErrFields returns the field names of error.details.fields, in order.
func (r Resp) ErrFields() []string {
	var out []string
	list, _ := r.ErrDetails()["fields"].([]any)
	for _, it := range list {
		m, _ := it.(map[string]any)
		f, _ := m["field"].(string)
		out = append(out, f)
	}
	return out
}

// ErrMessage returns error.message.
func (r Resp) ErrMessage() string {
	if e, ok := r.JSON()["error"].(map[string]any); ok {
		s, _ := e["message"].(string)
		return s
	}
	return ""
}

// Do sends a JSON request.
func (c *Client) Do(method, path string, body any) Resp {
	c.Env.T.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	return c.Raw(method, path, rd, map[string]string{"Content-Type": "application/json"})
}

// Raw sends a request with explicit headers; CSRF/cookie are added when set.
func (c *Client) Raw(method, path string, body io.Reader, headers map[string]string) Resp {
	c.Env.T.Helper()
	req, err := http.NewRequest(method, c.Env.HTTP.URL+path, body)
	if err != nil {
		c.Env.T.Fatal(err)
	}
	if c.Cookie != "" {
		req.AddCookie(&http.Cookie{Name: httpapi.SessionCookie, Value: c.Cookie})
	}
	if c.CSRF != "" && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", c.CSRF)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.Env.T.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return Resp{Status: resp.StatusCode, Header: resp.Header, Body: b}
}

// Get is Do("GET", ...).
func (c *Client) Get(path string) Resp { return c.Do("GET", path, nil) }

// MustID extracts a numeric id field from a JSON object.
func MustID(t testing.TB, m map[string]any, key string) int64 {
	t.Helper()
	f, ok := m[key].(float64)
	if !ok {
		t.Fatalf("field %q missing in %v", key, m)
	}
	return int64(f)
}

// RepoRoot finds the repository root (the directory holding dist/ and tests/).
func RepoRoot(t testing.TB) string {
	t.Helper()
	dir, _ := os.Getwd()
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "tests", "fixtures", "php")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("repository root with tests/fixtures not found")
	return ""
}

// Engines holds paths of the real engine binaries.
type Engines struct{ Root, Sast, Dast, Templates string }

// RealEngines locates dist/sdrscan-sast and dist/sdrscan-dast or skips the test.
func RealEngines(t testing.TB) Engines {
	t.Helper()
	root := RepoRoot(t)
	e := Engines{Root: root, Sast: filepath.Join(root, "dist", "sdrscan-sast"), Dast: filepath.Join(root, "dist", "sdrscan-dast"),
		Templates: filepath.Join(root, "dist", "templates", "php")}
	for _, p := range []string{e.Sast, e.Dast, e.Templates} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("engine artefact missing: %s", p)
		}
	}
	return e
}

// FakeResolver is a netguard resolver backed by a map (no real DNS in tests).
type FakeResolver map[string][]string

// LookupIPAddr implements the resolver interface.
func (f FakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, s := range f[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

// DefaultResolver maps the example hosts used by tests to public addresses and
// a few hostile names to private ones.
func DefaultResolver() FakeResolver {
	return FakeResolver{
		"shop.example.com":  {"93.184.216.34"},
		"shop2.example.com": {"93.184.216.35"},
		"internal.example":  {"10.0.0.7"},
		"rebind.example":    {"93.184.216.34", "127.0.0.1"},
		"git.example.com":   {"93.184.216.40"},
	}
}

// VulnFixtures locates the repository's vulnerability database fixture (tests/fixtures/vulndb), the
// SCA fixture project (tests/fixtures/sca/php-vulnerable) and the real dist/sdrscan-vuln, or skips.
type VulnFixtures struct{ DB, SCAProject, VulnBin string }

// RealVulnFixtures returns the fixture paths; DB is a directory that tests must treat as read-only.
func RealVulnFixtures(t testing.TB) VulnFixtures {
	t.Helper()
	root := RepoRoot(t)
	f := VulnFixtures{DB: filepath.Join(root, "tests", "fixtures", "vulndb"), SCAProject: filepath.Join(root, "tests", "fixtures", "sca", "php-vulnerable"),
		VulnBin: filepath.Join(root, "dist", "sdrscan-vuln")}
	for _, p := range []string{filepath.Join(f.DB, "meta.json"), f.SCAProject, f.VulnBin} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("vulnerability fixture missing: %s", p)
		}
	}
	return f
}
