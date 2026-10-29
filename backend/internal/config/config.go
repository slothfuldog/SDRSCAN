// Package config reads the process configuration from the environment.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// Config is the validated process configuration.
type Config struct {
	DatabaseURL string
	Listen      string

	SastBin   string
	DastBin   string
	Templates string
	Workdir   string

	Workers      int
	SastTimeout  time.Duration
	DastTimeout  time.Duration
	CloneTimeout time.Duration

	SecretKey       []byte // 32 bytes, nil when unset
	GitKnownHosts   string
	GitAllowedHosts []string

	AllowedHosts []string
	CookieSecure bool
	TrustProxy   bool

	MaxBodyBytes int64
	MaxResults   int

	SecretRules []string

	BootstrapAdminUser     string
	BootstrapAdminPassword string

	LogLevel  string
	LogFormat string

	AutoMigrate bool

	SchedulerEnabled bool
	MinIntervalSAST  time.Duration
	MinIntervalDAST  time.Duration

	// WebDir, when set, serves the frontend from disk instead of the embedded copy.
	WebDir string

	// Unsafe switches, test and local-demo use only. Both default to false and
	// log a loud warning at start when enabled.
	TestAllowLocalRepos      bool
	TestAllowPrivateNetworks bool
	// AllowPrivateNetworks lets git clones and DAST scans reach private networks (loopback,
	// RFC 1918, CGNAT, ULA, link-local). Default true; SDRSCAN_ALLOW_PRIVATE_NETWORKS=false turns
	// it off. Cloud metadata endpoints stay blocked either way.
	AllowPrivateNetworks bool
	// DASTCACert: PEM file of trusted CAs for HTTPS DAST targets (SDRSCAN_DAST_CA_CERT).
	DASTCACert string
	// DASTInsecureTLS: skip target certificate verification (SDRSCAN_DAST_INSECURE_TLS). Unsafe.
	DASTInsecureTLS bool

	// Vulnerability (CVE) support. VulnDB is the database directory (SDRSCAN_VULN_DB); empty means
	// CVE checks are off. VulnBin is the sdrscan-vuln executable (SDRSCAN_VULN_BIN) used by the Admin
	// update job. ScaEnabled (SDRSCAN_SCA_ENABLED, default true) is the master switch for passing the
	// database to the engines. VulnUpdateCron (SDRSCAN_VULN_UPDATE_CRON, UTC, empty = never) schedules updates.
	VulnDB            string
	VulnBin           string
	VulnUpdateTimeout time.Duration
	ScaEnabled        bool
	VulnUpdateCron    string
	// VulnCACert: PEM file with the CA(s) the updater trusts (SDRSCAN_VULN_CA_CERT, passed as --ca-cert), for internal proxies/CAs.
	VulnCACert string
}

// Default returns a Config populated with TRD defaults (no env read).
func Default() Config {
	return Config{
		AllowPrivateNetworks: true,
		Listen:               "127.0.0.1:8080",
		SastBin:              "sdrscan-sast",
		DastBin:              "sdrscan-dast",
		Templates:            "/opt/sdrscan/templates",
		Workdir:              "/tmp/sdrscan",
		Workers:              2,
		SastTimeout:          30 * time.Minute,
		DastTimeout:          60 * time.Minute,
		CloneTimeout:         5 * time.Minute,
		CookieSecure:         true,
		MaxBodyBytes:         50 << 20,
		MaxResults:           100000,
		SecretRules:          []string{"php-hardcoded-secret"},
		LogLevel:             "info",
		LogFormat:            "text",
		AutoMigrate:          true,
		SchedulerEnabled:     true,
		MinIntervalSAST:      15 * time.Minute,
		MinIntervalDAST:      60 * time.Minute,

		VulnBin:           "sdrscan-vuln",
		VulnUpdateTimeout: 60 * time.Minute,
		ScaEnabled:        true,
	}
}

// FromEnv reads the environment, applying defaults, and validates the result.
func FromEnv() (Config, error) {
	c := Default()
	var errs []error
	get := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }

	c.DatabaseURL = get("DATABASE_URL")
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if v := get("SDRSCAN_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := get("SDRSCAN_SAST_BIN"); v != "" {
		c.SastBin = absPath(v)
	}
	if v := get("SDRSCAN_DAST_BIN"); v != "" {
		c.DastBin = absPath(v)
	}
	if v := get("SDRSCAN_TEMPLATES"); v != "" {
		c.Templates = absPath(v)
	}
	if v := get("SDRSCAN_WORKDIR"); v != "" {
		c.Workdir = absPath(v)
	}
	if v := get("SDRSCAN_WORKERS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 64 {
			errs = append(errs, fmt.Errorf("SDRSCAN_WORKERS must be an integer 1..64"))
		} else {
			c.Workers = n
		}
	}
	if v := get("SDRSCAN_SCAN_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("SDRSCAN_SCAN_TIMEOUT must be a positive duration such as 30m"))
		} else {
			c.SastTimeout, c.DastTimeout = d, d
		}
	}
	if v := get("SDRSCAN_SECRET_KEY"); v != "" {
		k, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			k, err = base64.RawStdEncoding.DecodeString(v)
		}
		if err != nil || len(k) != 32 {
			errs = append(errs, errors.New("SDRSCAN_SECRET_KEY must be 32 bytes, base64 encoded"))
		} else {
			c.SecretKey = k
		}
	}
	c.GitKnownHosts = absPath(get("SDRSCAN_GIT_KNOWN_HOSTS"))
	c.GitAllowedHosts = splitList(get("SDRSCAN_GIT_ALLOWED_HOSTS"))
	c.AllowedHosts = splitList(get("SDRSCAN_ALLOWED_HOSTS"))
	if v := get("SDRSCAN_COOKIE_SECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, errors.New("SDRSCAN_COOKIE_SECURE must be true or false"))
		}
		c.CookieSecure = b
	}
	if v := get("SDRSCAN_TRUST_PROXY"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, errors.New("SDRSCAN_TRUST_PROXY must be true or false"))
		}
		c.TrustProxy = b
	}
	if v := get("SDRSCAN_MAX_BODY_MB"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			errs = append(errs, errors.New("SDRSCAN_MAX_BODY_MB must be a positive integer"))
		} else {
			c.MaxBodyBytes = int64(n) << 20
		}
	}
	if v := get("SDRSCAN_MAX_RESULTS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			errs = append(errs, errors.New("SDRSCAN_MAX_RESULTS must be a positive integer"))
		} else {
			c.MaxResults = n
		}
	}
	if v := get("SDRSCAN_SECRET_RULES"); v != "" {
		c.SecretRules = append(c.SecretRules, splitList(v)...)
	}
	c.BootstrapAdminUser = get("SDRSCAN_BOOTSTRAP_ADMIN_USER")
	c.BootstrapAdminPassword = get("SDRSCAN_BOOTSTRAP_ADMIN_PASSWORD")
	if f := get("SDRSCAN_BOOTSTRAP_ADMIN_PASSWORD_FILE"); f != "" && c.BootstrapAdminPassword == "" {
		b, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, fmt.Errorf("SDRSCAN_BOOTSTRAP_ADMIN_PASSWORD_FILE: %w", err))
		} else {
			c.BootstrapAdminPassword = strings.TrimRight(string(b), "\r\n")
		}
	}
	if v := get("SDRSCAN_LOG_LEVEL"); v != "" {
		c.LogLevel = strings.ToLower(v)
	}
	if v := get("SDRSCAN_LOG_FORMAT"); v != "" {
		c.LogFormat = strings.ToLower(v)
	}
	if v := get("SDRSCAN_AUTO_MIGRATE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, errors.New("SDRSCAN_AUTO_MIGRATE must be true or false"))
		}
		c.AutoMigrate = b
	}
	if v := get("SDRSCAN_SCHEDULER_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, errors.New("SDRSCAN_SCHEDULER_ENABLED must be true or false"))
		}
		c.SchedulerEnabled = b
	}
	for k, dst := range map[string]*time.Duration{"SDRSCAN_SCHEDULE_MIN_INTERVAL_SAST": &c.MinIntervalSAST, "SDRSCAN_SCHEDULE_MIN_INTERVAL_DAST": &c.MinIntervalDAST} {
		if v := get(k); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d < time.Minute {
				errs = append(errs, fmt.Errorf("%s must be a duration of at least 1m, such as 15m", k))
			} else {
				*dst = d
			}
		}
	}
	c.WebDir = absPath(get("SDRSCAN_WEB_DIR"))
	c.TestAllowLocalRepos = envBool(get("SDRSCAN_TEST_ALLOW_LOCAL_REPOS"))
	c.TestAllowPrivateNetworks = envBool(get("SDRSCAN_TEST_ALLOW_PRIVATE_NETWORKS"))
	c.AllowPrivateNetworks = true
	if v := get("SDRSCAN_ALLOW_PRIVATE_NETWORKS"); v != "" {
		c.AllowPrivateNetworks = envBool(v)
	}
	c.DASTCACert = absPath(get("SDRSCAN_DAST_CA_CERT"))
	c.DASTInsecureTLS = envBool(get("SDRSCAN_DAST_INSECURE_TLS"))
	c.VulnDB = absPath(get("SDRSCAN_VULN_DB"))
	if v := get("SDRSCAN_VULN_BIN"); v != "" {
		c.VulnBin = absPath(v)
	}
	if v := get("SDRSCAN_VULN_UPDATE_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			errs = append(errs, errors.New("SDRSCAN_VULN_UPDATE_TIMEOUT must be a duration of at least 1m, such as 60m"))
		} else {
			c.VulnUpdateTimeout = d
		}
	}
	if v := get("SDRSCAN_SCA_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, errors.New("SDRSCAN_SCA_ENABLED must be true or false"))
		} else {
			c.ScaEnabled = b
		}
	}
	c.VulnCACert = absPath(get("SDRSCAN_VULN_CA_CERT"))
	c.VulnUpdateCron = get("SDRSCAN_VULN_UPDATE_CRON")
	if c.VulnUpdateCron != "" {
		if err := validateUpdateCron(c.VulnUpdateCron); err != nil {
			errs = append(errs, fmt.Errorf("SDRSCAN_VULN_UPDATE_CRON: %w", err))
		}
	}

	if len(c.AllowedHosts) == 0 {
		c.AllowedHosts = DefaultAllowedHosts(c.Listen)
	}
	if err := errors.Join(errs...); err != nil {
		return c, err
	}
	return c, nil
}

// validateUpdateCron checks a 5-field cron expression (UTC) whose runs are at least one hour apart:
// the vulnerability feeds are public services and must not be polled more often.
func validateUpdateCron(expr string) error {
	sched, err := cron.ParseStandard(expr)
	if err != nil {
		return errors.New("must be a valid 5-field cron expression (UTC), such as \"30 3 * * *\"")
	}
	prev := sched.Next(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	for i := 0; i < 100; i++ {
		next := sched.Next(prev)
		if next.IsZero() {
			break
		}
		if next.Sub(prev) < time.Hour {
			return errors.New("runs must be at least 1 hour apart")
		}
		prev = next
	}
	return nil
}

// absPath makes file paths absolute so they keep working when an engine is started from another
// working directory (each scan runs in its own work dir). Bare command names are left for PATH lookup.
func absPath(v string) string {
	if v == "" || !strings.ContainsRune(v, filepath.Separator) {
		return v
	}
	if abs, err := filepath.Abs(v); err == nil {
		return abs
	}
	return v
}

func envBool(v string) bool {
	b, _ := strconv.ParseBool(v)
	return b
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DefaultAllowedHosts returns the Host header values accepted by default: the
// listen address plus localhost.
func DefaultAllowedHosts(listen string) []string {
	hosts := []string{"localhost", "127.0.0.1", "[::1]"}
	if listen != "" {
		hosts = append(hosts, listen)
		if i := strings.LastIndex(listen, ":"); i >= 0 {
			hosts = append(hosts, listen[:i])
		}
	}
	return hosts
}
