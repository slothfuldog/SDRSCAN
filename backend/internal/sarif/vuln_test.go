package sarif_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/sarif"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func TestNormalizeAdvisoryID(t *testing.T) {
	good := map[string]string{
		"CVE-2021-44228":       "CVE-2021-44228",
		" cve-2021-44228 ":     "CVE-2021-44228",
		"CVE-2024-1234567":     "CVE-2024-1234567",
		"GHSA-JFH8-C2JP-5V3Q":  "GHSA-jfh8-c2jp-5v3q",
		"ghsa-jfh8-c2jp-5v3q":  "GHSA-jfh8-c2jp-5v3q",
		"RUSTSEC-2021-0001":    "RUSTSEC-2021-0001",
		"go-2021-0001":         "GO-2021-0001",
		"pksa-6gx3-abcd-1234":  "PKSA-6gx3-abcd-1234",
		"PYSEC-2021-1":         "PYSEC-2021-1",
		"OSV-2020-1234":        "OSV-2020-1234",
		"GHSA-xxxx-xxxx-xxxx2": "",                    // length of the random part
		"GHSA-2099-FRAM-0001":  "GHSA-2099-fram-0001", // the repository fixtures use 0 and 1
	}
	for in, want := range good {
		got, ok := sarif.NormalizeAdvisoryID(in)
		if want == "" {
			if ok {
				t.Errorf("%q accepted as %q", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("%q -> %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "CVE-21-1", "CVE-2021-12", "CVE-2021-44228x", "CVE-2021-44228 OR 1=1", "GHSA-aaaa-bbbb",
		"<script>", "javascript:alert(1)", "../etc", strings.Repeat("A", 70), "CVE-2021-4422\n8", "A-1", "-CVE-2021-1"} {
		if got, ok := sarif.NormalizeAdvisoryID(bad); ok {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func parseVuln(t *testing.T, ruleID, js string) (*sarif.Vulnerability, bool) {
	t.Helper()
	return sarif.ParseVulnerability(json.RawMessage(js), ruleID)
}

func TestParseVulnerabilityFull(t *testing.T) {
	v, ok := parseVuln(t, "CVE-2021-1111", `{
		"ids": ["cve-2021-1111", "GHSA-JFH8-C2JP-5V3Q", "CVE-2021-1111", "not an id", 42],
		"package": {"ecosystem": "Packagist", "name": "vendor/pkg", "version": "1.2.3", "extra": "x"},
		"fixed_versions": ["1.2.4", "", "2.0.0"],
		"source": "OSV",
		"references": ["https://example.com/a", "javascript:alert(1)", "http://example.com/b", "ftp://x/y", "https://u:p@example.com/", "https://example.com/c",
			"https://example.com/d", "https://example.com/e", "https://example.com/f", "https://example.com/g"],
		"cvss": {"score": 9.84, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		"confidence": "HIGH", "scope": "runtime"}`)
	if !ok {
		t.Fatal("rejected")
	}
	if strings.Join(v.IDs, ",") != "CVE-2021-1111,GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("ids: %v", v.IDs)
	}
	if v.Package == nil || v.Package.Name != "vendor/pkg" || v.Package.Version != "1.2.3" || v.Package.Ecosystem != "Packagist" {
		t.Errorf("package: %+v", v.Package)
	}
	if strings.Join(v.FixedVersions, ",") != "1.2.4,2.0.0" {
		t.Errorf("fixed: %v", v.FixedVersions)
	}
	if v.Source == nil || *v.Source != "osv" || v.Confidence == nil || *v.Confidence != "high" || v.Scope == nil || *v.Scope != "runtime" {
		t.Errorf("enums: %v %v %v", v.Source, v.Confidence, v.Scope)
	}
	if len(v.References) != 5 || v.References[0] != "https://example.com/a" || v.References[1] != "http://example.com/b" || v.References[2] != "https://example.com/c" {
		t.Errorf("references (http/https only, max 5, no userinfo): %v", v.References)
	}
	if v.CVSS == nil || v.CVSS.Score != 9.8 || v.CVSS.Vector == nil || !strings.HasPrefix(*v.CVSS.Vector, "CVSS:3.1/") {
		t.Errorf("cvss: %+v", v.CVSS)
	}
	b, _ := json.Marshal(v)
	for _, k := range []string{`"ids"`, `"package"`, `"fixed_versions"`, `"source"`, `"references"`, `"cvss"`, `"confidence"`, `"scope"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("stored JSON lacks %s: %s", k, b)
		}
	}
}

func TestParseVulnerabilityDropsInvalidFieldsButKeepsTheFinding(t *testing.T) {
	v, ok := parseVuln(t, "CVE-2020-0001", `{"package": "oops", "fixed_versions": "1.0", "source": "evil", "references": ["javascript:x"],
		"cvss": {"score": 11, "vector": "x"}, "confidence": "certain", "scope": "prod"}`)
	if !ok {
		t.Fatal("a vulnerability with a valid rule id must survive invalid fields")
	}
	if len(v.IDs) != 1 || v.IDs[0] != "CVE-2020-0001" {
		t.Errorf("ids fall back to the rule id: %v", v.IDs)
	}
	if v.Package != nil || len(v.FixedVersions) != 0 || v.Source != nil || len(v.References) != 0 || v.CVSS != nil || v.Confidence != nil || v.Scope != nil {
		t.Errorf("invalid fields must be dropped: %+v", v)
	}
	// DAST shape: product instead of name.
	d, ok := parseVuln(t, "CVE-2021-23017", `{"ids": ["CVE-2021-23017"], "package": {"product": "nginx", "version": "1.18.0"}, "confidence": "low"}`)
	if !ok || d.Package == nil || d.Package.Product != "nginx" || d.Package.Name != "" || d.Confidence == nil || *d.Confidence != "low" {
		t.Errorf("dast: %+v", d)
	}
	// Control characters and over-long text are not accepted in names.
	c, _ := parseVuln(t, "CVE-2021-1111", `{"package": {"name": "a\u0000b", "version": "1"}}`)
	if c.Package != nil {
		t.Errorf("control characters in the package name: %+v", c.Package)
	}
	l, _ := parseVuln(t, "CVE-2021-1111", `{"package": {"name": "x", "version": "`+strings.Repeat("9", 300)+`"}}`)
	if l.Package == nil || l.Package.Version != "" {
		t.Errorf("over-long version must be dropped: %+v", l.Package)
	}
}

func TestParseVulnerabilityUnusable(t *testing.T) {
	for name, tc := range map[string]struct{ rule, js string }{
		"not an object":         {"CVE-2021-1111", `"CVE-2021-1111"`},
		"array":                 {"CVE-2021-1111", `[1,2]`},
		"null":                  {"CVE-2021-1111", `null`},
		"no id and a code rule": {"php-sql-injection", `{"package": {"name": "x"}}`},
		"only invalid ids":      {"php-xss", `{"ids": ["x y", "'; drop table"]}`},
		"too large":             {"CVE-2021-1111", `{"ids": ["CVE-2021-1111"], "pad": "` + strings.Repeat("a", sarif.MaxVulnerabilityBytes) + `"}`},
	} {
		if v, ok := parseVuln(t, tc.rule, tc.js); ok {
			t.Errorf("%s accepted: %+v", name, v)
		}
	}
	// At most 20 ids.
	var ids []string
	for i := 0; i < 30; i++ {
		ids = append(ids, "CVE-2021-"+strings.Repeat("1", 4)+string(rune('0'+i%10))+string(rune('0'+i/10)))
	}
	b, _ := json.Marshal(map[string]any{"ids": ids})
	v, ok := sarif.ParseVulnerability(b, "x")
	if !ok || len(v.IDs) != sarif.MaxVulnIDs {
		t.Errorf("ids cap: %v %d", ok, len(v.IDs))
	}
}

func TestVulnerabilityInResultsAndSeverityFromCVSS(t *testing.T) {
	d := testutil.Doc{Results: []testutil.SResult{
		{Rule: "CVE-2021-1111", URI: "composer.lock", Line: 12, Level: "error", Message: "m", Vuln: map[string]any{
			"ids": []string{"CVE-2021-1111"}, "package": map[string]any{"ecosystem": "Packagist", "name": "a/b", "version": "1.0.0"},
			"cvss": map[string]any{"score": 9.1}}},
		{Rule: "CVE-2021-2222", URI: "composer.lock", Line: 20, Level: "note", Message: "m", Score: "5.0", Vuln: map[string]any{"ids": []string{"CVE-2021-2222"}, "cvss": map[string]any{"score": 9.9}}},
		{Rule: "php-xss-echo", URI: "a.php", Line: 3, Level: "error", Message: "m", Vuln: "garbage"},
		{Rule: "php-xss-echo", URI: "b.php", Line: 3, Level: "error", Message: "m"},
	}}
	run, err := parse(t, d)
	if err != nil {
		t.Fatal(err)
	}
	r := run.Results
	if r[0].Vulnerability == nil || r[0].Severity != "critical" {
		t.Errorf("severity must fall back to the CVSS score: %+v", r[0])
	}
	if r[1].Vulnerability == nil || r[1].Severity != "medium" {
		t.Errorf("security-severity wins over the CVSS score: %s", r[1].Severity)
	}
	if r[2].Vulnerability != nil || !r[2].VulnerabilityIgnored {
		t.Errorf("garbage is ignored and flagged: %+v", r[2])
	}
	if r[3].Vulnerability != nil || r[3].VulnerabilityIgnored {
		t.Errorf("plain finding: %+v", r[3])
	}
}
