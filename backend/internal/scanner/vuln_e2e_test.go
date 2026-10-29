package scanner_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

// copyDir copies a directory tree (the fixture database is never modified in place).
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func vulnObj(t *testing.T, f store.Finding) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(f.Vulnerability, &m); err != nil {
		t.Fatalf("%s: %v", f.RuleID, err)
	}
	return m
}

func projectFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			files[e.Name()] = string(b)
		}
	}
	return files
}

func TestE2ESastScaWithRealEngineAndFixtureDatabase(t *testing.T) {
	e := testutil.RealEngines(t)
	vf := testutil.RealVulnFixtures(t)
	r := newRig(t, rigOpts{guard: local(), runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates, VulnDB: vf.DB}})
	cb := r.repoCB("sca", makeRepo(t, projectFiles(t, vf.SCAProject)))
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if !strings.Contains(logOf(sc), "CVE checks enabled") || strings.Contains(logOf(sc), vf.DB) {
		t.Fatalf("log:\n%s", logOf(sc))
	}
	fs, total, err := r.env.Store.ListFindings(context.Background(), store.FindingFilter{CodebaseID: cb.ID, Kind: "vulnerability"}, store.Page{Page: 1, Size: 20})
	if err != nil || total != 3 {
		t.Fatalf("want 3 vulnerability findings, got %d (%v)", total, err)
	}
	want := map[string]struct{ sev, scope, pkg string }{
		"CVE-2099-0001": {"critical", "runtime", "acme/web-framework"},
		"CVE-2099-0004": {"low", "runtime", "acme/version-zoo"},
		"CVE-2099-0002": {"medium", "dev", "acme/dev-tool"},
	}
	for _, f := range fs {
		w, ok := want[f.RuleID]
		if !ok {
			t.Fatalf("unexpected finding %s", f.RuleID)
		}
		delete(want, f.RuleID)
		if f.Severity != w.sev || f.Confidence != "normal" || f.LocationKind != "file" || f.Path == nil || *f.Path != "composer.lock" || f.StartLine == nil {
			t.Errorf("%s: %+v", f.RuleID, f)
		}
		v := string(f.Vulnerability)
		vo := vulnObj(t, f)
		pk, _ := vo["package"].(map[string]any)
		if vo["scope"] != w.scope || pk["name"] != w.pkg || pk["ecosystem"] != "Packagist" || vo["source"] != "osv" || vo["confidence"] != "high" {
			t.Errorf("%s: vulnerability: %s", f.RuleID, v)
		}
		if fv, _ := vo["fixed_versions"].([]any); len(fv) != 1 {
			t.Errorf("%s: fixed_versions: %s", f.RuleID, v)
		}
		if len(f.VulnIDs) < 2 || f.VulnIDs[0] != f.RuleID {
			t.Errorf("%s: ids (CVE first, aliases kept): %v", f.RuleID, f.VulnIDs)
		}
		if f.RuleID == "CVE-2099-0001" && (vo["cvss"].(map[string]any)["score"] != 9.8 || f.VulnIDs[1] != "GHSA-2099-fram-0001" || !strings.Contains(v, "https://example.test/advisories/framework")) {
			t.Errorf("CVE-2099-0001 details: %s", v)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing findings: %v", want)
	}
	cbRow, _ := r.env.Store.GetCodebase(context.Background(), cb.ID)
	if cbRow.NCritical != 1 || cbRow.NMedium != 1 || cbRow.NLow != 1 || cbRow.NHigh != 0 {
		t.Fatalf("summary: %+v", cbRow.Counts())
	}
	// By alias, through the store filter used by the API.
	if _, n, _ := r.env.Store.ListFindings(context.Background(), store.FindingFilter{CodebaseID: cb.ID, CVE: "GHSA-2099-dev0-0001"}, store.Page{Page: 1, Size: 5}); n != 1 {
		t.Fatalf("search by alias: %d", n)
	}
	r.assertWorkdirClean()
}

func TestE2ESastScaDisabledOrWithoutDatabaseStillSucceeds(t *testing.T) {
	e := testutil.RealEngines(t)
	vf := testutil.RealVulnFixtures(t)
	files := projectFiles(t, vf.SCAProject)
	for name, cfg := range map[string]scanner.Config{
		"sca disabled":       {VulnDB: vf.DB, ScaDisabled: true},
		"not configured":     {},
		"directory missing":  {VulnDB: filepath.Join(t.TempDir(), "absent")},
		"engine reads empty": {VulnDB: t.TempDir()}, // exists, but holds no database: the engine skips SCA with a warning
	} {
		t.Run(name, func(t *testing.T) {
			cfg.SastBin, cfg.DastBin, cfg.Templates = e.Sast, e.Dast, e.Templates
			r := newRig(t, rigOpts{guard: local(), runner: cfg})
			cb := r.repoCB("sca", makeRepo(t, files))
			sc := r.run(r.enqueue(cb))
			if sc.Status != "succeeded" {
				t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
			}
			if n := r.countFindings(cb.ID); n != 0 {
				t.Fatalf("no CVE findings without a usable database, got %d", n)
			}
			if name == "engine reads empty" && !strings.Contains(logOf(sc), "engine warning") {
				t.Errorf("the engine's warning belongs in the job log:\n%s", logOf(sc))
			}
		})
	}
}

// An old database only produces a warning (and still produces findings): the scan does not fail.
func TestE2EOldDatabaseWarnsButDoesNotFailTheScan(t *testing.T) {
	e := testutil.RealEngines(t)
	vf := testutil.RealVulnFixtures(t)
	db := t.TempDir()
	copyDir(t, vf.DB, db)
	meta, _ := os.ReadFile(filepath.Join(db, "meta.json"))
	if err := os.WriteFile(filepath.Join(db, "meta.json"), []byte(strings.ReplaceAll(string(meta), "2026-10-20T00:00:00Z", "2020-01-01T00:00:00Z")), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, rigOpts{guard: local(), runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates, VulnDB: db}})
	cb := r.repoCB("old", makeRepo(t, projectFiles(t, vf.SCAProject)))
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" || r.countFindings(cb.ID) != 3 {
		t.Fatalf("%s %s findings=%d\n%s", sc.Status, codeOf(sc), r.countFindings(cb.ID), logOf(sc))
	}
	if !strings.Contains(logOf(sc), "engine warning:") || !strings.Contains(logOf(sc), "vulnerability database") && !strings.Contains(logOf(sc), "basis data") {
		t.Errorf("log should carry the age warning:\n%s", logOf(sc))
	}
	if strings.Contains(logOf(sc), db) {
		t.Errorf("the database path must not be logged:\n%s", logOf(sc))
	}
}

func TestE2EDastCveWithRealEngineAndFixtureDatabase(t *testing.T) {
	e := testutil.RealEngines(t)
	vf := testutil.RealVulnFixtures(t)
	db := t.TempDir()
	copyDir(t, vf.DB, db)
	// The fixture is 8 days old; a fresh timestamp keeps the engine from warning (not required, tidier).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	r := newRig(t, rigOpts{
		guard:  &netguard.Guard{AllowLoopback: true, Resolver: testutil.DefaultResolver()},
		runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates, VulnDB: db},
	})
	cb := r.urlCB("live", srv.URL, true)
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" || sc.Type != "dast" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	fs, _, err := r.env.Store.ListFindings(context.Background(), store.FindingFilter{CodebaseID: cb.ID, Kind: "vulnerability"}, store.Page{Page: 1, Size: 20})
	if err != nil || len(fs) != 3 {
		t.Fatalf("want 3 CVE findings from the Server/X-Powered-By banners, got %d (%v)", len(fs), err)
	}
	got := map[string]store.Finding{}
	for _, f := range fs {
		got[f.RuleID] = f
	}
	for _, id := range []string{"CVE-2099-1000", "CVE-2099-1001", "CVE-2099-1200"} {
		f, ok := got[id]
		if !ok {
			t.Fatalf("missing %s in %v", id, got)
		}
		vo := vulnObj(t, f)
		pk, _ := vo["package"].(map[string]any)
		if f.LocationKind != "url" || f.URL == nil || !strings.HasPrefix(*f.URL, srv.URL) || vo["confidence"] != "low" || vo["source"] != "nvd" ||
			!strings.HasPrefix(pk["product"].(string), "cpe:2.3:a:") || pk["version"] == "" {
			t.Errorf("%s: %+v", id, f)
		}
		// Product decision: low-confidence CVE findings are listed and counted.
		if f.Confidence != "normal" {
			t.Errorf("%s finding confidence %q", id, f.Confidence)
		}
	}
	if got["CVE-2099-1200"].Severity != "critical" || !strings.Contains(got["CVE-2099-1000"].Snippet, "Server: Apache/2.4.41") {
		t.Errorf("severity/evidence: %+v", got["CVE-2099-1200"])
	}
	cbRow, _ := r.env.Store.GetCodebase(context.Background(), cb.ID)
	if cbRow.NCritical < 1 || cbRow.NLowConfidence != 0 {
		t.Fatalf("summary: %+v low=%d", cbRow.Counts(), cbRow.NLowConfidence)
	}
}
