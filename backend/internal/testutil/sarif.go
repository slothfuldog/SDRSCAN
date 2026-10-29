package testutil

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// FP returns a deterministic 64-hex fingerprint for a seed.
func FP(seed string) string {
	s := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(s[:])
}

// RuleMeta is one entry of tool.driver.rules[].
type RuleMeta struct {
	ID    string
	Score string // security-severity ("" = none)
	Tags  []string
	Level string
}

// SResult is one SARIF result for the builder.
type SResult struct {
	Rule     string
	URI      string
	Message  string
	Snippet  string
	Line     int
	Col      int
	Level    string
	Score    string // result-level security-severity
	Low      bool
	Evidence string
	FP       string // default: FP(rule|uri|snippet)
	NoFP     bool
	FPKey    string // override the fingerprint key
	// Vuln is written as properties.vulnerability when non-nil (any JSON-encodable value, so tests
	// can also send malformed shapes).
	Vuln any
}

// Doc describes a SARIF document.
type Doc struct {
	Engine  string // default sdrscan-sast
	Version string // default 2.1.0
	Partial bool
	Scanned []string
	Rules   []RuleMeta
	Results []SResult
	Runs    int // number of identical runs (default 1)
}

// Build renders the document.
func (d Doc) Build() []byte {
	if d.Engine == "" {
		d.Engine = "sdrscan-sast"
	}
	if d.Version == "" {
		d.Version = "2.1.0"
	}
	rules := []any{}
	for _, r := range d.Rules {
		props := map[string]any{"tags": r.Tags}
		if r.Score != "" {
			props["security-severity"] = r.Score
		}
		rules = append(rules, map[string]any{"id": r.ID, "properties": props, "defaultConfiguration": map[string]any{"level": r.Level}})
	}
	results := []any{}
	for _, r := range d.Results {
		loc := map[string]any{"artifactLocation": map[string]any{"uri": r.URI}}
		if r.Line > 0 || r.Snippet != "" {
			col := r.Col
			if col == 0 {
				col = 1
			}
			rg := map[string]any{"startLine": r.Line, "startColumn": col, "endLine": r.Line, "endColumn": col + 10}
			if r.Snippet != "" {
				rg["snippet"] = map[string]any{"text": r.Snippet}
			}
			loc["region"] = rg
		}
		res := map[string]any{"ruleId": r.Rule, "level": r.Level, "message": map[string]any{"text": r.Message},
			"locations": []any{map[string]any{"physicalLocation": loc}}}
		if r.Level == "" {
			delete(res, "level")
		}
		if !r.NoFP {
			fp := r.FP
			if fp == "" {
				fp = FP(r.Rule + "|" + r.URI + "|" + r.Snippet)
			}
			key := r.FPKey
			if key == "" {
				key = "sdrscanFingerprint/v1"
			}
			res["partialFingerprints"] = map[string]any{key: fp}
		}
		props := map[string]any{}
		if r.Score != "" {
			props["security-severity"] = r.Score
		}
		if r.Low {
			props["confidence"] = "low"
		}
		if r.Evidence != "" {
			props["evidence"] = r.Evidence
		}
		if r.Vuln != nil {
			props["vulnerability"] = r.Vuln
		}
		if len(props) > 0 {
			res["properties"] = props
		}
		results = append(results, res)
	}
	run := map[string]any{"tool": map[string]any{"driver": map[string]any{"name": d.Engine, "version": "0.1.0", "rules": rules}}, "results": results}
	if d.Partial {
		run["properties"] = map[string]any{"scanKind": "partial", "scannedFiles": d.Scanned}
	}
	n := d.Runs
	if n == 0 {
		n = 1
	}
	runs := make([]any, n)
	for i := range runs {
		runs[i] = run
	}
	b, _ := json.Marshal(map[string]any{"version": d.Version, "runs": runs})
	return b
}

// StdRules are the rules used by most tests.
var StdRules = []RuleMeta{
	{ID: "php-sql-injection", Score: "9.5", Tags: []string{"security", "external/cwe/cwe-89"}, Level: "error"},
	{ID: "php-xss-echo", Score: "7.5", Tags: []string{"security", "external/cwe/cwe-79"}, Level: "error"},
	{ID: "php-weak-password-hash", Score: "5.0", Tags: []string{"security", "external/cwe/cwe-327"}, Level: "warning"},
	{ID: "php-hardcoded-secret", Score: "8.0", Tags: []string{"security", "secrets", "external/cwe/cwe-798"}, Level: "error"},
	{ID: "php-info", Score: "0.5", Tags: []string{"security"}, Level: "note"},
}
