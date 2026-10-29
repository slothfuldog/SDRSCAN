package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func setenv(t *testing.T, kv map[string]string) {
	for _, k := range []string{"DATABASE_URL", "SDRSCAN_LISTEN", "SDRSCAN_WORKERS", "SDRSCAN_SECRET_KEY", "SDRSCAN_COOKIE_SECURE",
		"SDRSCAN_TEST_ALLOW_LOCAL_REPOS", "SDRSCAN_TEST_ALLOW_PRIVATE_NETWORKS", "SDRSCAN_ALLOW_PRIVATE_NETWORKS", "SDRSCAN_SECRET_RULES", "SDRSCAN_SCAN_TIMEOUT"} {
		t.Setenv(k, "")
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestDefaultsAndRequired(t *testing.T) {
	setenv(t, nil)
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("DATABASE_URL must be required: %v", err)
	}
	setenv(t, map[string]string{"DATABASE_URL": "postgres://x"})
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8080" || c.Workers != 2 || !c.CookieSecure || c.TestAllowLocalRepos || c.TestAllowPrivateNetworks || c.MaxBodyBytes != 50<<20 || c.MaxResults != 100000 {
		t.Fatalf("defaults: %+v", c)
	}
	if c.SastTimeout.Minutes() != 30 || c.DastTimeout.Minutes() != 60 || !c.AutoMigrate {
		t.Fatalf("timeouts: %+v", c)
	}
}

func TestValidation(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(make([]byte, 32))
	setenv(t, map[string]string{"DATABASE_URL": "postgres://x", "SDRSCAN_SECRET_KEY": good, "SDRSCAN_WORKERS": "4", "SDRSCAN_SECRET_RULES": "my-rule, other"})
	c, err := FromEnv()
	if err != nil || len(c.SecretKey) != 32 || c.Workers != 4 || len(c.SecretRules) != 3 {
		t.Fatalf("%+v %v", c, err)
	}
	for k, v := range map[string]string{"SDRSCAN_SECRET_KEY": "c2hvcnQ=", "SDRSCAN_WORKERS": "0", "SDRSCAN_COOKIE_SECURE": "maybe", "SDRSCAN_SCAN_TIMEOUT": "soon"} {
		setenv(t, map[string]string{"DATABASE_URL": "postgres://x", k: v})
		if _, err := FromEnv(); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
	setenv(t, map[string]string{"DATABASE_URL": "postgres://x", "SDRSCAN_TEST_ALLOW_PRIVATE_NETWORKS": "true", "SDRSCAN_TEST_ALLOW_LOCAL_REPOS": "1"})
	if c, _ := FromEnv(); !c.TestAllowPrivateNetworks || !c.TestAllowLocalRepos {
		t.Fatal("test switches not read")
	}
}

func TestAllowPrivateNetworksSwitch(t *testing.T) {
	setenv(t, map[string]string{"DATABASE_URL": "postgres://x"})
	if c, _ := FromEnv(); !c.AllowPrivateNetworks || c.TestAllowPrivateNetworks {
		t.Fatal("private networks must be allowed by default, without enabling the test switch")
	}
	setenv(t, map[string]string{"DATABASE_URL": "postgres://x", "SDRSCAN_ALLOW_PRIVATE_NETWORKS": "false"})
	if c, _ := FromEnv(); c.AllowPrivateNetworks {
		t.Fatal("SDRSCAN_ALLOW_PRIVATE_NETWORKS=false must turn private networks off")
	}
}

func TestPathsBecomeAbsolute(t *testing.T) {
	setenv(t, map[string]string{
		"DATABASE_URL":      "postgres://x",
		"SDRSCAN_SAST_BIN":  "../dist/sdrscan-sast",
		"SDRSCAN_DAST_BIN":  "sdrscan-dast", // bare name: left for PATH lookup
		"SDRSCAN_TEMPLATES": "./templates",
	})
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{"sast": c.SastBin, "templates": c.Templates} {
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			t.Errorf("%s path not absolute/clean: %q", name, p)
		}
	}
	if c.DastBin != "sdrscan-dast" {
		t.Errorf("bare command name must stay as is: %q", c.DastBin)
	}
}

func TestVulnerabilityConfig(t *testing.T) {
	for _, k := range []string{"SDRSCAN_VULN_DB", "SDRSCAN_VULN_BIN", "SDRSCAN_VULN_UPDATE_TIMEOUT", "SDRSCAN_SCA_ENABLED", "SDRSCAN_VULN_UPDATE_CRON"} {
		t.Setenv(k, "")
	}
	setenv(t, map[string]string{"DATABASE_URL": "postgres://x"})
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.VulnDB != "" || c.VulnBin != "sdrscan-vuln" || c.VulnUpdateTimeout.Minutes() != 60 || !c.ScaEnabled || c.VulnUpdateCron != "" {
		t.Fatalf("defaults: %+v", c)
	}
	setenv(t, map[string]string{"DATABASE_URL": "postgres://x"})
	t.Setenv("SDRSCAN_VULN_DB", "./vulndb")
	t.Setenv("SDRSCAN_VULN_BIN", "../dist/sdrscan-vuln")
	t.Setenv("SDRSCAN_VULN_UPDATE_TIMEOUT", "90m")
	t.Setenv("SDRSCAN_SCA_ENABLED", "false")
	t.Setenv("SDRSCAN_VULN_UPDATE_CRON", "30 3 * * *")
	t.Setenv("SDRSCAN_VULN_CA_CERT", "./ca.pem")
	c, err = FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.VulnDB, "/") || !strings.HasPrefix(c.VulnBin, "/") || strings.Contains(c.VulnBin, "..") || c.VulnUpdateTimeout.Minutes() != 90 || c.ScaEnabled || c.VulnUpdateCron != "30 3 * * *" || !strings.HasPrefix(c.VulnCACert, "/") {
		t.Fatalf("values: %+v", c)
	}
	for k, v := range map[string]string{"SDRSCAN_VULN_UPDATE_TIMEOUT": "10s", "SDRSCAN_SCA_ENABLED": "maybe", "SDRSCAN_VULN_UPDATE_CRON": "every day",
		"SDRSCAN_VULN_UPDATE_CRON ": "x"} {
		setenv(t, map[string]string{"DATABASE_URL": "postgres://x"})
		t.Setenv("SDRSCAN_VULN_UPDATE_TIMEOUT", "")
		t.Setenv("SDRSCAN_SCA_ENABLED", "")
		t.Setenv("SDRSCAN_VULN_UPDATE_CRON", "")
		t.Setenv(strings.TrimSpace(k), v)
		if _, err := FromEnv(); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
	// A cron that runs more often than hourly is refused.
	setenv(t, map[string]string{"DATABASE_URL": "postgres://x"})
	t.Setenv("SDRSCAN_VULN_UPDATE_CRON", "*/10 * * * *")
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "1 hour") {
		t.Errorf("too frequent cron: %v", err)
	}
}
