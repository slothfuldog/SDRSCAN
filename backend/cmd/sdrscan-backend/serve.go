package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/auth"
	"github.com/sdrscan/sdrscan/backend/internal/config"
	"github.com/sdrscan/sdrscan/backend/internal/crypt"
	"github.com/sdrscan/sdrscan/backend/internal/db"
	"github.com/sdrscan/sdrscan/backend/internal/httpapi"
	"github.com/sdrscan/sdrscan/backend/internal/ingest"
	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/vulndb"
	"github.com/sdrscan/sdrscan/backend/internal/webui"
)

func newLogger(c config.Config) *slog.Logger {
	var lvl slog.Level
	switch c.LogLevel {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if c.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "", "listen address (overrides SDRSCAN_LISTEN)")
	workers := fs.Int("workers", 0, "number of scan workers (overrides SDRSCAN_WORKERS)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
		if os.Getenv("SDRSCAN_ALLOWED_HOSTS") == "" {
			cfg.AllowedHosts = config.DefaultAllowedHosts(cfg.Listen)
		}
	}
	if *workers > 0 {
		cfg.Workers = *workers
	}
	log := newLogger(cfg)
	slog.SetDefault(log)
	if cfg.TestAllowLocalRepos {
		log.Warn("UNSAFE: SDRSCAN_TEST_ALLOW_LOCAL_REPOS is on; local paths and file:// repositories are accepted. Test/demo only.")
	}
	if cfg.TestAllowPrivateNetworks {
		log.Warn("UNSAFE: SDRSCAN_TEST_ALLOW_PRIVATE_NETWORKS is on; git hosts and DAST targets may be on private/loopback networks and the engine runs with --allow-private-networks-for-tests. Test/demo only.")
	}
	if cfg.AllowPrivateNetworks {
		log.Info("private networks are allowed for git hosts and DAST targets (set SDRSCAN_ALLOW_PRIVATE_NETWORKS=false to refuse them); cloud metadata endpoints stay blocked")
	} else {
		log.Info("private networks are refused for git hosts and DAST targets (SDRSCAN_ALLOW_PRIVATE_NETWORKS=false)")
	}
	if !cfg.CookieSecure {
		log.Warn("session cookies are not marked Secure (SDRSCAN_COOKIE_SECURE=false); use only without TLS on localhost")
	}

	box, err := crypt.New(cfg.SecretKey)
	if err != nil {
		return err
	}
	guard := &netguard.Guard{AllowLocalRepos: cfg.TestAllowLocalRepos, AllowLoopback: cfg.TestAllowPrivateNetworks, AllowPrivate: cfg.AllowPrivateNetworks, GitAllowedHosts: lower(cfg.GitAllowedHosts)}

	runCtx, stopRun := context.WithCancel(context.Background())
	defer stopRun()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	pool, err := db.Connect(runCtx, cfg.DatabaseURL, true)
	if err != nil {
		return err
	}
	defer pool.Close()
	if cfg.AutoMigrate {
		if err := db.Migrate(runCtx, pool); err != nil {
			return err
		}
	}
	st := store.New(pool)

	ing := ingest.New(st, ingest.Config{MaxResults: cfg.MaxResults, SecretRules: cfg.SecretRules})
	run := scanner.New(st, ing, guard, box, scanner.Config{
		SastBin: cfg.SastBin, DastBin: cfg.DastBin, Templates: cfg.Templates, Workdir: cfg.Workdir, Workers: cfg.Workers,
		SastTimeout: cfg.SastTimeout, DastTimeout: cfg.DastTimeout, CloneTimeout: cfg.CloneTimeout, GitKnownHosts: cfg.GitKnownHosts,
		MaxSarifBytes: cfg.MaxBodyBytes, DastAllowPrivate: cfg.TestAllowPrivateNetworks, DastBlockPrivateNetworks: !cfg.AllowPrivateNetworks,
		DastCACert: cfg.DASTCACert, DastInsecureTLS: cfg.DASTInsecureTLS,
		VulnDB: cfg.VulnDB, ScaDisabled: !cfg.ScaEnabled,
	}, log)
	vdb := vulndb.New(runCtx, vulndb.Config{Dir: cfg.VulnDB, Bin: cfg.VulnBin, Timeout: cfg.VulnUpdateTimeout, Workdir: cfg.Workdir,
		ScaEnabled: cfg.ScaEnabled, Cron: cfg.VulnUpdateCron, CACert: cfg.VulnCACert}, st, log)
	switch {
	case cfg.VulnDB == "":
		log.Info("CVE checks are off (SDRSCAN_VULN_DB is not set)")
		if cfg.VulnUpdateCron != "" {
			log.Warn("SDRSCAN_VULN_UPDATE_CRON is ignored because SDRSCAN_VULN_DB is not set")
		}
	case !cfg.ScaEnabled:
		log.Info("CVE checks are off (SDRSCAN_SCA_ENABLED=false)")
	default:
		log.Info("CVE checks configured", "db_present", vdb.DirPresent(), "vuln_tool", vdb.ToolAvailable(), "update_cron", cfg.VulnUpdateCron)
		if !vdb.DirPresent() {
			log.Warn("the vulnerability database directory does not exist yet; install it with an Admin update (Vulnerability database page)")
		}
	}

	// Engines must be runnable (checked with --version).
	vctx, vcancel := context.WithTimeout(runCtx, 15*time.Second)
	sastV, err := run.EngineVersion(vctx, "sast")
	if err != nil {
		vcancel()
		return fmt.Errorf("SDRSCAN_SAST_BIN (%s): %w", cfg.SastBin, err)
	}
	dastV, err := run.EngineVersion(vctx, "dast")
	vcancel()
	if err != nil {
		return fmt.Errorf("SDRSCAN_DAST_BIN (%s): %w", cfg.DastBin, err)
	}
	log.Info("engines ready", "sast", sastV, "dast", dastV)

	if err := bootstrapAdmin(runCtx, st, cfg, log); err != nil {
		return err
	}

	web, err := webui.New(cfg.WebDir)
	if err != nil {
		return fmt.Errorf("SDRSCAN_WEB_DIR: %w", err)
	}
	if !web.HasFrontend() {
		log.Warn("no frontend is embedded; serving the placeholder page (see README: building the web UI)")
	}

	done := make(chan struct{})
	api := httpapi.New(st, ing, box, guard, web, log, httpapi.Options{
		Version: version, AllowedHosts: cfg.AllowedHosts, CookieSecure: cfg.CookieSecure, TrustProxy: cfg.TrustProxy,
		MaxBodyBytes: cfg.MaxBodyBytes, MinIntervalSAST: cfg.MinIntervalSAST, MinIntervalDAST: cfg.MinIntervalDAST,
		EngineVersions: func() (string, string) { return sastV, dastV },
	})
	api.Done = done
	api.VulnDB = vdb
	api.LoginTester = run

	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Minute, // large SARIF uploads
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	if h, _, err := net.SplitHostPort(cfg.Listen); err == nil && h != "127.0.0.1" && h != "localhost" && h != "::1" {
		log.Warn("listening on a non-loopback address; put a TLS reverse proxy in front and do not expose to the internet", "addr", cfg.Listen)
	}

	run.Start(runCtx)
	var bg sync.WaitGroup
	bg.Add(2)
	go func() {
		defer bg.Done()
		if !cfg.SchedulerEnabled {
			log.Info("scheduler disabled (SDRSCAN_SCHEDULER_ENABLED=false)")
			return
		}
		(&scanner.Scheduler{Store: st, Log: log, OnTick: vdb.ScheduledTick}).Run(runCtx)
	}()
	go func() {
		defer bg.Done()
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			_, _ = st.PurgeSessions(runCtx, 8*time.Hour)
			select {
			case <-runCtx.Done():
				return
			case <-t.C:
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	log.Info("sdrscan-backend listening", "addr", cfg.Listen, "version", version, "workers", cfg.Workers)

	select {
	case sig := <-sigCh:
		log.Info("shutting down", "signal", sig.String())
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	close(done)
	sctx, scancel := context.WithTimeout(context.Background(), 30*time.Second)
	_ = srv.Shutdown(sctx)
	scancel()
	cancelBase()
	stopRun() // cancels running jobs (status cancelled, work dirs removed)
	run.Wait()
	vdb.Wait()
	bg.Wait()
	log.Info("stopped")
	return nil
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// bootstrapAdmin creates the first Admin from the environment when no user exists.
func bootstrapAdmin(ctx context.Context, st *store.Store, cfg config.Config, log *slog.Logger) error {
	n, err := st.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if cfg.BootstrapAdminUser == "" || cfg.BootstrapAdminPassword == "" {
		log.Warn("no users exist; create the first Admin with `sdrscan-backend user create --role admin` or set SDRSCAN_BOOTSTRAP_ADMIN_USER and SDRSCAN_BOOTSTRAP_ADMIN_PASSWORD")
		return nil
	}
	if err := auth.ValidatePassword(cfg.BootstrapAdminPassword, cfg.BootstrapAdminUser, ""); err != nil {
		return fmt.Errorf("bootstrap admin password: %w", err)
	}
	h, err := auth.NewHasher().Hash(cfg.BootstrapAdminPassword)
	if err != nil {
		return err
	}
	if _, err := st.CreateUser(ctx, cfg.BootstrapAdminUser, h, "admin", true, true); err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}
	log.Info("bootstrap admin created; the password must be changed at first login", "username", cfg.BootstrapAdminUser)
	return nil
}
