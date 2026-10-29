package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sdrscan/sdrscan/backend/internal/dastauth"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

// authFilePrefix names the credential file in the job directory.
const authFilePrefix = "auth-"

// LoginCheckTimeout bounds POST /codebases/{id}/dast-auth/test.
const LoginCheckTimeout = 30 * time.Second

// Errors of TestLogin.
var (
	ErrNoAuth            = errors.New("no DAST authentication is configured")
	ErrEngineUnsupported = errors.New("the sdrscan-dast engine does not support authenticated scans")
	ErrAuthUnreadable    = errors.New("the stored DAST authentication cannot be decrypted")
	// ErrNoLogin: only fixed headers/cookies are configured; the engine's --login-check needs a login form.
	ErrNoLogin = errors.New("no login form is configured")
)

// dastNetArgs are the network-policy flags shared by every sdrscan-dast invocation.
func (r *Runner) dastNetArgs() []string {
	var args []string
	if r.Cfg.DastAllowPrivate {
		args = append(args, "--allow-private-networks-for-tests")
	} else if r.Cfg.DastBlockPrivateNetworks {
		args = append(args, "--block-private-networks")
	}
	if r.Cfg.DastCACert != "" {
		args = append(args, "--ca-cert", r.Cfg.DastCACert)
	}
	if r.Cfg.DastInsecureTLS {
		args = append(args, "--insecure")
	}
	return args
}

// openAuth decrypts the stored configuration and re-checks that the login URL still belongs to the
// target origin (credentials must never be sent to another host).
func (r *Runner) openAuth(cb store.Codebase) (dastauth.Config, *jobFailure) {
	cfg, err := OpenAuth(r.Box, cb)
	switch {
	case errors.Is(err, ErrAuthUnreadable):
		return cfg, fail("auth_unreadable", "the stored DAST authentication cannot be decrypted (check SDRSCAN_SECRET_KEY)")
	case err != nil:
		return cfg, fail("auth_unreadable", "the stored DAST authentication is invalid; set it again")
	}
	return cfg, nil
}

// OpenAuth decrypts the DAST authentication of cb.
func OpenAuth(box interface{ Open([]byte) ([]byte, error) }, cb store.Codebase) (dastauth.Config, error) {
	var cfg dastauth.Config
	if !cb.HasDastAuth() || len(cb.DastAuthEnc) == 0 {
		return cfg, ErrNoAuth
	}
	plain, err := box.Open(cb.DastAuthEnc)
	if err != nil {
		return cfg, ErrAuthUnreadable
	}
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return cfg, fmt.Errorf("stored authentication is invalid")
	}
	if cb.BaseURL == nil || (cfg.Login != nil && !dastauth.SameOrigin(cfg.Login.URL, *cb.BaseURL)) {
		return cfg, fmt.Errorf("stored authentication does not match the target origin")
	}
	return cfg, nil
}

// writeAuthFile writes the engine's --auth-file (mode 0600) in dir.
func writeAuthFile(dir string, cfg dastauth.Config) (string, *jobFailure) {
	body, err := dastauth.EngineFile(cfg)
	if err != nil {
		return "", fail("auth_unreadable", "cannot prepare the authentication file")
	}
	f, err := os.CreateTemp(dir, authFilePrefix+"*.json") // created with mode 0600
	if err != nil {
		return "", fail("auth_unreadable", "cannot create the authentication file")
	}
	path := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return "", fail("auth_unreadable", "cannot secure the authentication file")
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return "", fail("auth_unreadable", "cannot write the authentication file")
	}
	if err := f.Close(); err != nil {
		return "", fail("auth_unreadable", "cannot write the authentication file")
	}
	ok = true
	return path, nil
}

// crawlArgs returns the crawl flags, nil when the engine has no --crawl (the scan then runs
// without crawling), or a failure when exclusions or limits cannot be honoured: a user's
// exclusions must never be dropped silently.
func crawlArgs(cb store.Codebase, fl map[string]bool) ([]string, *jobFailure) {
	if !fl["--crawl"] {
		return nil, nil
	}
	if !fl["--max-depth"] || !fl["--max-pages"] || (len(cb.DastCrawlExclude) > 0 && !fl["--exclude-path"]) {
		return nil, fail("engine_unsupported", "this sdrscan-dast engine cannot honour the crawl limits or exclusions; the scan was not run")
	}
	args := []string{"--crawl", "--max-depth", strconv.Itoa(cb.DastCrawlMaxDepth), "--max-pages", strconv.Itoa(cb.DastCrawlMaxPages)}
	for _, p := range cb.DastCrawlExclude {
		args = append(args, "--exclude-path", p)
	}
	return args, nil
}

var (
	pagesBefore = regexp.MustCompile(`(?i)\b(\d{1,6})\s+(?:halaman|pages?)\b`)
	pagesAfter  = regexp.MustCompile(`(?i)\b(?:halaman|pages?)\b[^\d\n]{0,40}?(\d{1,6})\b`)
)

// pagesScanned extracts the number of crawled pages from the engine's stderr summary
// (for example "halaman dipindai: 12" or "12 halaman"). Warning lines are ignored.
func pagesScanned(stderr string) (int, bool) {
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		if line == "" || strings.HasPrefix(low, "peringatan:") || strings.HasPrefix(low, "warning:") {
			continue
		}
		for _, re := range []*regexp.Regexp{pagesBefore, pagesAfter} {
			if m := re.FindStringSubmatch(line); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil {
					return n, true
				}
			}
		}
	}
	return 0, false
}

var (
	activeReqBefore = regexp.MustCompile(`(?i)\b(\d{1,7})\s+(?:active requests?|permintaan aktif)\b`)
	activeReqAfter  = regexp.MustCompile(`(?i)\b(?:active requests?|permintaan aktif)\b[^\d\n]{0,40}?(\d{1,7})\b`)
)

// activeRequestsSent extracts the number of active-scan test requests from the engine's stderr summary
// (for example "N active requests sent" or "N permintaan aktif dikirim"). Warning lines are ignored.
func activeRequestsSent(stderr string) (int, bool) {
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		if line == "" || strings.HasPrefix(low, "peringatan:") || strings.HasPrefix(low, "warning:") {
			continue
		}
		for _, re := range []*regexp.Regexp{activeReqBefore, activeReqAfter} {
			if m := re.FindStringSubmatch(line); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil {
					return n, true
				}
			}
		}
	}
	return 0, false
}

// LoginCheck is the result of a login test.
type LoginCheck struct {
	OK      bool
	Message string
}

// TestLogin runs `sdrscan-dast scan <base_url> --auth-file ... --login-check` synchronously (30 s
// limit). The message is the engine's summary with every credential value redacted. Errors:
// ErrNoAuth, ErrEngineUnsupported, ErrAuthUnreadable; engine failures are reported as OK=false.
func (r *Runner) TestLogin(ctx context.Context, cb store.Codebase) (LoginCheck, error) {
	cfg, err := OpenAuth(r.Box, cb)
	if err != nil {
		return LoginCheck{}, err
	}
	if cfg.Login == nil {
		return LoginCheck{}, ErrNoLogin
	}
	fl := r.engineFlags("dast")
	if !fl["--auth-file"] || !fl["--login-check"] {
		return LoginCheck{}, ErrEngineUnsupported
	}
	if err := os.MkdirAll(r.Cfg.Workdir, 0o700); err != nil {
		return LoginCheck{}, err
	}
	dir, err := os.MkdirTemp(r.Cfg.Workdir, "scan-logincheck-")
	if err != nil {
		return LoginCheck{}, err
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0o700)
	path, jf := writeAuthFile(dir, cfg)
	if jf != nil {
		return LoginCheck{}, errors.New(jf.msg)
	}
	secrets := dastauth.Secrets(cfg)
	args := append([]string{"scan"}, r.dastNetArgs()...)
	args = append(args, *cb.BaseURL, "--auth-file", path, "--login-check")
	tctx, cancel := context.WithTimeout(ctx, LoginCheckTimeout)
	defer cancel()
	res := func() procResult {
		defer os.Remove(path)
		return runProc(tctx, procSpec{bin: r.Cfg.DastBin, args: args, env: r.engineEnv(dir), dir: dir,
			grace: r.Cfg.KillGrace, maxOut: 64 << 10})
	}()
	if ctx.Err() != nil {
		return LoginCheck{}, ctx.Err()
	}
	clean := func(s string) string {
		s = Sanitize(dastauth.Redact(strings.TrimSpace(s), secrets), secrets...)
		s = strings.ToValidUTF8(s, "")
		if utf8.RuneCountInString(s) > 500 {
			s = string([]rune(s)[:500]) + "..."
		}
		return s
	}
	switch {
	case tctx.Err() != nil:
		return LoginCheck{false, "The login check timed out after 30 seconds."}, nil
	case res.notFound:
		return LoginCheck{false, "The sdrscan-dast engine executable was not found."}, nil
	case res.exitCode == 0:
		msg := clean(res.stdout)
		if msg == "" {
			msg = "Login succeeded."
		}
		return LoginCheck{true, msg}, nil
	case res.exitCode == 2:
		msg := clean(lastLines(res.stderr, 5))
		if msg == "" {
			msg = clean(res.stdout)
		}
		if msg == "" {
			msg = "Login failed."
		}
		return LoginCheck{false, msg}, nil
	default:
		return LoginCheck{false, fmt.Sprintf("The engine exited with code %d.", res.exitCode)}, nil
	}
}
