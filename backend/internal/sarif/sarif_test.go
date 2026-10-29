package sarif_test

import (
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/sarif"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func parse(t *testing.T, d testutil.Doc) (*sarif.Run, *sarif.Error) {
	t.Helper()
	run, err := sarif.Parse(d.Build(), sarif.Options{})
	if err != nil {
		se, ok := err.(*sarif.Error)
		if !ok {
			t.Fatalf("unexpected error type %T", err)
		}
		return nil, se
	}
	return run, nil
}

func TestSeverityMapping(t *testing.T) {
	cases := []struct {
		score, level, want string
	}{
		{"9.0", "error", "critical"}, {"9.5", "error", "critical"},
		{"8.9", "error", "high"}, {"7.0", "error", "high"},
		{"6.9", "warning", "medium"}, {"4.0", "error", "medium"},
		{"3.9", "warning", "low"}, {"1.0", "note", "low"},
		{"0.9", "error", "info"}, {"0", "error", "info"},
		{"", "error", "high"}, {"", "warning", "medium"}, {"", "note", "low"}, {"", "", "info"},
	}
	for _, c := range cases {
		d := testutil.Doc{Results: []testutil.SResult{{Rule: "r", URI: "a.php", Line: 1, Level: c.level, Score: c.score}}}
		run, err := parse(t, d)
		if err != nil {
			t.Fatal(err)
		}
		if got := run.Results[0].Severity; got != c.want {
			t.Errorf("score=%q level=%q: got %s want %s", c.score, c.level, got, c.want)
		}
	}
	// Same level: error, different scores give critical vs high.
	d := testutil.Doc{Results: []testutil.SResult{
		{Rule: "a", URI: "a.php", Line: 1, Level: "error", Score: "9.5"},
		{Rule: "b", URI: "a.php", Line: 2, Level: "error", Score: "7.5"},
	}}
	run, _ := parse(t, d)
	if run.Results[0].Severity != "critical" || run.Results[1].Severity != "high" {
		t.Fatalf("critical vs high not distinguished: %+v", run.Results)
	}
}

func TestRuleSeverityFallbackAndCWE(t *testing.T) {
	d := testutil.Doc{Rules: testutil.StdRules, Results: []testutil.SResult{
		{Rule: "php-sql-injection", URI: "a.php", Line: 3, Level: "error"},
		{Rule: "php-sql-injection", URI: "b.php", Line: 3, Level: "error", Score: "2.0"}, // result overrides rule
	}}
	run, err := parse(t, d)
	if err != nil {
		t.Fatal(err)
	}
	if run.Results[0].Severity != "critical" || run.Results[1].Severity != "low" {
		t.Fatalf("severities: %s %s", run.Results[0].Severity, run.Results[1].Severity)
	}
	if r := run.Rules["php-sql-injection"]; len(r.CWE) != 1 || r.CWE[0] != "CWE-89" {
		t.Fatalf("cwe: %+v", r)
	}
	if !run.Rules["php-hardcoded-secret"].Secret {
		t.Fatal("secret rule not detected from tags")
	}
}

func TestInvalidDocuments(t *testing.T) {
	ok := testutil.Doc{Results: []testutil.SResult{{Rule: "r", URI: "a.php", Line: 1, Level: "note"}}}
	if _, err := parse(t, ok); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		doc  testutil.Doc
		code string
	}{
		{"version", testutil.Doc{Version: "2.0.0"}, "invalid_sarif"},
		{"two runs", testutil.Doc{Runs: 2}, "multiple_runs"},
		{"zero runs", testutil.Doc{Runs: -1}, ""},
		{"engine", testutil.Doc{Engine: "other"}, "unsupported_engine"},
		{"no fingerprint", testutil.Doc{Results: []testutil.SResult{{Rule: "r", URI: "a", Line: 1, NoFP: true}}}, "missing_fingerprint"},
		{"old key", testutil.Doc{Results: []testutil.SResult{{Rule: "r", URI: "a", Line: 1, FPKey: "primaryLocationLineHash"}}}, "missing_fingerprint"},
		{"short fp", testutil.Doc{Results: []testutil.SResult{{Rule: "r", URI: "a", Line: 1, FP: "abc"}}}, "missing_fingerprint"},
		{"no rule", testutil.Doc{Results: []testutil.SResult{{URI: "a", Line: 1}}}, "invalid_sarif"},
		{"no uri", testutil.Doc{Results: []testutil.SResult{{Rule: "r", Line: 1}}}, "invalid_sarif"},
		{"partial without files", testutil.Doc{Partial: true}, "invalid_sarif"},
	}
	for _, c := range cases {
		if c.doc.Runs < 0 {
			continue
		}
		_, err := parse(t, c.doc)
		if err == nil {
			t.Errorf("%s: expected an error", c.name)
			continue
		}
		if err.Code != c.code {
			t.Errorf("%s: code %s want %s (%s)", c.name, err.Code, c.code, err.Message)
		}
	}
	if _, err := sarif.Parse([]byte("{nope"), sarif.Options{}); err == nil {
		t.Error("broken JSON accepted")
	}
	if _, err := sarif.Parse(testutil.Doc{Results: make([]testutil.SResult, 3)}.Build(), sarif.Options{MaxResults: 2}); err == nil {
		t.Error("max results not enforced")
	}
	// Old-key message hints at updating the engine and names the index.
	_, e := parse(t, testutil.Doc{Results: []testutil.SResult{{Rule: "r", URI: "a", Line: 1, FPKey: "old/v0"}}})
	if e == nil || !strings.Contains(e.Message, "update") || e.Index != 0 {
		t.Errorf("old key error: %+v", e)
	}
}

func TestConfidenceAndEvidenceAndPartial(t *testing.T) {
	d := testutil.Doc{Partial: true, Scanned: []string{"a.php", "b.php"}, Results: []testutil.SResult{
		{Rule: "r", URI: "a.php", Line: 1, Level: "note", Low: true, Evidence: "X: y"},
	}}
	run, err := parse(t, d)
	if err != nil {
		t.Fatal(err)
	}
	if run.Kind != sarif.Partial || len(run.ScannedFiles) != 2 {
		t.Fatalf("partial not read: %+v", run)
	}
	if !run.Results[0].LowConfidence || run.Results[0].Evidence != "X: y" {
		t.Fatalf("result: %+v", run.Results[0])
	}
}

func TestNormalizePathAndURL(t *testing.T) {
	good := map[string]string{"src/a.php": "src/a.php", "./src/a.php": "src/a.php", "src\\a.php": "src/a.php", "src%20x/a.php": "src x/a.php"}
	for in, want := range good {
		got, err := sarif.NormalizePath(in)
		if err != nil || got != want {
			t.Errorf("NormalizePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"/etc/passwd", "../x", "a/../../x", "a/%2e%2e/x", "C:\\x", "file:///etc/passwd", "", strings.Repeat("a", 1025)} {
		if _, err := sarif.NormalizePath(bad); err == nil {
			t.Errorf("NormalizePath(%q) accepted", bad)
		}
	}
	if u, err := sarif.NormalizeURL("https://h.example/p?q=1#f"); err != nil || u != "https://h.example/p" {
		t.Errorf("NormalizeURL: %q %v", u, err)
	}
	for _, bad := range []string{"ftp://h/", "https://user:pw@h/", "https:///x", "javascript:alert(1)"} {
		if _, err := sarif.NormalizeURL(bad); err == nil {
			t.Errorf("NormalizeURL(%q) accepted", bad)
		}
	}
}
