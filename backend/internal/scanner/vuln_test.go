package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

// argsEngine is a fake engine that records its scan arguments (one per line) in argsFile, answers
// `scan --help` with the given flag list and copies sarif to --output.
func argsEngine(t *testing.T, sarif, argsFile, help string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "engine.sh")
	script := `#!/bin/sh
if [ "$1" = "scan" ] && [ "$2" = "--help" ]; then printf '%s\n' '` + help + `'; exit 0; fi
printf '%s\n' "$@" > '` + argsFile + `'
out=""
while [ $# -gt 0 ]; do case "$1" in --output) out="$2"; shift;; esac; shift; done
cp '` + sarif + `' "$out"
exit 0
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func scaSarif(t *testing.T) string {
	return writeSarif(t, testutil.Doc{Results: []testutil.SResult{{Rule: "CVE-2021-1111", URI: "composer.lock", Line: 12, Level: "error", Message: "m", Score: "8.0",
		Vuln: map[string]any{"ids": []string{"CVE-2021-1111"}, "package": map[string]any{"ecosystem": "Packagist", "name": "a/b", "version": "1.0.0"}}}}})
}

func recordedArgs(t *testing.T, f string) []string {
	t.Helper()
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("engine did not run: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func argAfter(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func TestSastPassesTheVulnerabilityDatabaseWhenAvailable(t *testing.T) {
	repo := makeRepo(t, map[string]string{"composer.lock": "{}\n"})
	db := t.TempDir()
	for _, c := range []struct {
		name      string
		vulnDB    string
		disabled  bool
		help      string
		want      bool
		logHas    string
		logHasNot string
	}{
		{"database present and engine supports it", db, false, "--templates --vuln-db <DIR>", true, "CVE checks enabled", db},
		{"sca disabled", db, true, "--templates --vuln-db <DIR>", false, "CVE checks are disabled", ""},
		{"directory missing", filepath.Join(db, "nope"), false, "--templates --vuln-db <DIR>", false, "directory not found", ""},
		{"older engine without the flag", db, false, "--templates", false, "does not support --vuln-db", ""},
		{"feature not configured", "", false, "--templates --vuln-db <DIR>", false, "", "CVE"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, rigOpts{guard: local(), runner: scanner.Config{VulnDB: c.vulnDB, ScaDisabled: c.disabled}})
			argsFile := filepath.Join(t.TempDir(), "args")
			r.env.Runner.Cfg.SastBin = argsEngine(t, scaSarif(t), argsFile, c.help)
			cb := r.repoCB("deps", repo)
			sc := r.run(r.enqueue(cb))
			if sc.Status != "succeeded" {
				t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
			}
			args := recordedArgs(t, argsFile)
			got, has := argAfter(args, "--vuln-db")
			if has != c.want || (c.want && got != c.vulnDB) {
				t.Fatalf("--vuln-db %q present=%v, want present=%v (%s): %v", got, has, c.want, c.vulnDB, args)
			}
			if c.logHas != "" && !strings.Contains(logOf(sc), c.logHas) {
				t.Errorf("log lacks %q:\n%s", c.logHas, logOf(sc))
			}
			if c.logHasNot != "" && strings.Contains(logOf(sc), c.logHasNot) {
				t.Errorf("log must not contain %q:\n%s", c.logHasNot, logOf(sc))
			}
			// The CVE finding is stored as a vulnerability.
			fs, _, err := r.env.Store.ListFindings(context.Background(), store.FindingFilter{CodebaseID: cb.ID, Kind: "vulnerability"}, store.Page{Page: 1, Size: 10})
			if err != nil || len(fs) != 1 || fs[0].RuleID != "CVE-2021-1111" || len(fs[0].VulnIDs) != 1 {
				t.Fatalf("stored findings: %+v %v", fs, err)
			}
		})
	}
}

func TestDastPassesTheVulnerabilityDatabase(t *testing.T) {
	db := t.TempDir()
	sarif := writeSarif(t, testutil.Doc{Engine: "sdrscan-dast", Results: []testutil.SResult{{Rule: "CVE-2021-23017", URI: "https://shop.example.com/", Level: "error", Message: "m", Score: "7.7",
		Vuln: map[string]any{"ids": []string{"CVE-2021-23017"}, "package": map[string]any{"product": "nginx", "version": "1.18.0"}, "confidence": "low", "source": "nvd"}}}})
	for _, disabled := range []bool{false, true} {
		r := newRig(t, rigOpts{guard: &netguard.Guard{Resolver: testutil.DefaultResolver()}, runner: scanner.Config{VulnDB: db, ScaDisabled: disabled}})
		argsFile := filepath.Join(t.TempDir(), "args")
		r.env.Runner.Cfg.DastBin = argsEngine(t, sarif, argsFile, "--max-rps --vuln-db <DIR>")
		cb := r.urlCB("live", "https://shop.example.com", true)
		sc := r.run(r.enqueue(cb))
		if sc.Status != "succeeded" {
			t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
		}
		got, has := argAfter(recordedArgs(t, argsFile), "--vuln-db")
		if has == disabled || (has && got != db) {
			t.Fatalf("disabled=%v: --vuln-db %q present=%v", disabled, got, has)
		}
		// A low-confidence CVE finding is counted (product decision).
		cbRow, _ := r.env.Store.GetCodebase(context.Background(), cb.ID)
		if cbRow.NHigh != 1 || cbRow.NLowConfidence != 0 {
			t.Fatalf("summary: %+v", cbRow)
		}
	}
}
