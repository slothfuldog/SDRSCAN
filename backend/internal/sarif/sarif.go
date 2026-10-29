// Package sarif reads SARIF 2.1.0 produced by sdrscan-sast and sdrscan-dast.
// The reader is deliberately loose (unknown fields are ignored); strict checks
// that need database context live in the ingest layer.
package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Engine tool names accepted.
const (
	EngineSAST = "sdrscan-sast"
	EngineDAST = "sdrscan-dast"
)

// FingerprintKey is the partialFingerprints key carrying the finding identity.
const FingerprintKey = "sdrscanFingerprint/v1"

// ScanKind distinguishes a full scan from a partial (changed files) scan.
type ScanKind string

const (
	Full    ScanKind = "full"
	Partial ScanKind = "partial"
)

// Severity labels in ascending order.
var severityOrder = []string{"info", "low", "medium", "high", "critical"}

// Rank returns 0 (info) to 4 (critical).
func Rank(sev string) int {
	for i, s := range severityOrder {
		if s == sev {
			return i
		}
	}
	return 0
}

// Error is a typed SARIF validation error. Index is the zero-based result
// index when the problem is tied to one result, otherwise -1.
type Error struct {
	Code    string
	Message string
	Index   int
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func newErr(code string, idx int, format string, a ...any) *Error {
	return &Error{Code: code, Index: idx, Message: fmt.Sprintf(format, a...)}
}

// Rule is the metadata of one rule from tool.driver.rules[].
type Rule struct {
	ID               string
	SecuritySeverity *float64
	Tags             []string
	CWE              []string
	Secret           bool
}

// Region is a source region (1-based) and its snippet.
type Region struct {
	StartLine, StartColumn, EndLine, EndColumn int
	Snippet                                    string
}

// Result is one parsed SARIF result.
type Result struct {
	Index         int
	RuleID        string
	Severity      string
	LowConfidence bool
	Message       string
	URI           string // raw artifactLocation.uri
	Region        *Region
	Fingerprint   string
	Evidence      string // properties.evidence (DAST)
	// Vulnerability is the validated properties.vulnerability (CVE finding); nil for code findings.
	Vulnerability *Vulnerability
	// VulnerabilityIgnored is true when properties.vulnerability was present but unusable.
	VulnerabilityIgnored bool
}

// Run is the single run of a SARIF document.
type Run struct {
	ToolName, ToolVersion string
	Kind                  ScanKind
	ScannedFiles          []string
	HasScannedFiles       bool
	Rules                 map[string]*Rule
	Results               []Result
}

type docT struct {
	Version string `json:"version"`
	Runs    []runT `json:"runs"`
}

type runT struct {
	Tool struct {
		Driver struct {
			Name    string  `json:"name"`
			Version string  `json:"version"`
			Rules   []ruleT `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Properties map[string]json.RawMessage `json:"properties"`
	Results    []resultT                  `json:"results"`
}

type ruleT struct {
	ID         string                     `json:"id"`
	Properties map[string]json.RawMessage `json:"properties"`
}

type resultT struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region *struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
				EndLine     int `json:"endLine"`
				EndColumn   int `json:"endColumn"`
				Snippet     *struct {
					Text string `json:"text"`
				} `json:"snippet"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	PartialFingerprints map[string]string          `json:"partialFingerprints"`
	Properties          map[string]json.RawMessage `json:"properties"`
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Options tune the reader.
type Options struct {
	MaxResults int
}

// Read parses a SARIF document from r, refusing more than maxBytes bytes.
func Read(r io.Reader, maxBytes int64, opt Options) (*Run, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, newErr("payload_too_large", -1, "SARIF exceeds %d bytes", maxBytes)
	}
	return Parse(b, opt)
}

// Parse parses and validates the structure of a SARIF document.
func Parse(data []byte, opt Options) (*Run, error) {
	var d docT
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&d); err != nil {
		return nil, newErr("invalid_sarif", -1, "Body is not valid JSON: %v", err)
	}
	if d.Version != "2.1.0" {
		return nil, newErr("invalid_sarif", -1, "SARIF version must be 2.1.0 (got %q).", d.Version)
	}
	if len(d.Runs) != 1 {
		return nil, newErr("multiple_runs", -1, "SARIF must contain exactly one run (got %d).", len(d.Runs))
	}
	rt := d.Runs[0]
	name := rt.Tool.Driver.Name
	if name != EngineSAST && name != EngineDAST {
		return nil, newErr("unsupported_engine", -1, "tool.driver.name must be %q or %q (got %q).", EngineSAST, EngineDAST, name)
	}
	if opt.MaxResults > 0 && len(rt.Results) > opt.MaxResults {
		return nil, newErr("too_many_results", -1, "SARIF has %d results; the limit is %d.", len(rt.Results), opt.MaxResults)
	}
	run := &Run{
		ToolName:    name,
		ToolVersion: rt.Tool.Driver.Version,
		Kind:        Full,
		Rules:       map[string]*Rule{},
	}
	for _, r := range rt.Tool.Driver.Rules {
		if r.ID == "" {
			continue
		}
		rule := &Rule{ID: r.ID}
		rule.SecuritySeverity = floatProp(r.Properties["security-severity"])
		var tags []string
		if raw, ok := r.Properties["tags"]; ok {
			_ = json.Unmarshal(raw, &tags)
		}
		rule.Tags = tags
		for _, t := range tags {
			lt := strings.ToLower(t)
			if strings.HasPrefix(lt, "external/cwe/cwe-") {
				n := lt[len("external/cwe/cwe-"):]
				if isDigits(n) {
					rule.CWE = append(rule.CWE, "CWE-"+n)
				}
			}
			if lt == "secrets" {
				rule.Secret = true
			}
		}
		for _, c := range rule.CWE {
			if c == "CWE-798" {
				rule.Secret = true
			}
		}
		run.Rules[r.ID] = rule
	}
	if raw, ok := rt.Properties["scanKind"]; ok {
		var k string
		_ = json.Unmarshal(raw, &k)
		if k == "partial" {
			run.Kind = Partial
		}
	}
	if raw, ok := rt.Properties["scannedFiles"]; ok && string(bytes.TrimSpace(raw)) != "null" {
		var files []string
		if err := json.Unmarshal(raw, &files); err != nil {
			return nil, newErr("invalid_sarif", -1, "run.properties.scannedFiles must be an array of strings.")
		}
		run.ScannedFiles = files
		run.HasScannedFiles = true
	}
	if run.Kind == Partial && !run.HasScannedFiles {
		return nil, newErr("invalid_sarif", -1, "A partial scan must list run.properties.scannedFiles.")
	}
	run.Results = make([]Result, 0, len(rt.Results))
	for i, r := range rt.Results {
		if r.RuleID == "" {
			return nil, newErr("invalid_sarif", i, "Result %d has no ruleId.", i)
		}
		if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			return nil, newErr("invalid_sarif", i, "Result %d has no locations[0].physicalLocation.artifactLocation.uri.", i)
		}
		fp := r.PartialFingerprints[FingerprintKey]
		if !hex64.MatchString(fp) {
			msg := fmt.Sprintf("Result %d has no valid partialFingerprints[%q] (64 hex characters).", i, FingerprintKey)
			if fp == "" && len(r.PartialFingerprints) > 0 {
				msg += " The SARIF uses an older fingerprint key; update sdrscan to a version that writes " + FingerprintKey + "."
			}
			return nil, newErr("missing_fingerprint", i, "%s", msg)
		}
		res := Result{
			Index:       i,
			RuleID:      r.RuleID,
			Message:     r.Message.Text,
			URI:         r.Locations[0].PhysicalLocation.ArtifactLocation.URI,
			Fingerprint: fp,
		}
		if rg := r.Locations[0].PhysicalLocation.Region; rg != nil {
			res.Region = &Region{StartLine: rg.StartLine, StartColumn: rg.StartColumn, EndLine: rg.EndLine, EndColumn: rg.EndColumn}
			if rg.Snippet != nil {
				res.Region.Snippet = rg.Snippet.Text
			}
			if res.Region.StartLine <= 0 && res.Region.Snippet == "" {
				res.Region = nil
			}
		}
		var conf string
		if raw, ok := r.Properties["confidence"]; ok {
			_ = json.Unmarshal(raw, &conf)
		}
		res.LowConfidence = strings.EqualFold(conf, "low")
		if raw, ok := r.Properties["evidence"]; ok {
			_ = json.Unmarshal(raw, &res.Evidence)
		}
		if raw, ok := r.Properties["vulnerability"]; ok && string(bytes.TrimSpace(raw)) != "null" {
			if v, ok := ParseVulnerability(raw, r.RuleID); ok {
				res.Vulnerability = v
			} else {
				res.VulnerabilityIgnored = true
			}
		}
		// Severity: result security-severity, then rule's, then the CVSS score of a
		// vulnerability, then level.
		score := floatProp(r.Properties["security-severity"])
		if score == nil {
			if rule := run.Rules[r.RuleID]; rule != nil {
				score = rule.SecuritySeverity
			}
		}
		if score == nil && res.Vulnerability != nil && res.Vulnerability.CVSS != nil {
			c := res.Vulnerability.CVSS.Score
			score = &c
		}
		res.Severity = SeverityFor(score, r.Level)
		run.Results = append(run.Results, res)
	}
	return run, nil
}

// SeverityFor maps a CVSS-like score (preferred) or a SARIF level to a label.
func SeverityFor(score *float64, level string) string {
	if score != nil {
		switch s := *score; {
		case s >= 9.0:
			return "critical"
		case s >= 7.0:
			return "high"
		case s >= 4.0:
			return "medium"
		case s >= 1.0:
			return "low"
		default:
			return "info"
		}
	}
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	}
	return "info"
}

func floatProp(raw json.RawMessage) *float64 {
	if len(raw) == 0 {
		return nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return &f
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
			return &v
		}
	}
	return nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// NormalizePath turns an artifact URI into a scan-root-relative path with '/'
// separators. It rejects absolute paths, '..' segments and overlong paths.
func NormalizePath(uri string) (string, error) {
	p := uri
	if strings.HasPrefix(strings.ToLower(p), "file://") {
		return "", fmt.Errorf("absolute file URI %q is not allowed", uri)
	}
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	} else {
		return "", fmt.Errorf("invalid percent-encoding in path")
	}
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if strings.HasPrefix(p, "/") || (len(p) >= 2 && p[1] == ':') {
		return "", fmt.Errorf("absolute path %q is not allowed", uri)
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("path contains NUL")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", fmt.Errorf("path %q contains '..'", uri)
		}
	}
	if len(p) > 1024 {
		return "", fmt.Errorf("path is longer than 1024 characters")
	}
	return p, nil
}

// NormalizeURL validates a DAST location: http(s), no userinfo; query and
// fragment are dropped.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("URL scheme must be http or https")
	}
	if u.User != nil {
		return "", fmt.Errorf("URL must not contain userinfo")
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("URL has no host")
	}
	u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = "", "", "", false
	out := u.String()
	if len(out) > 2048 {
		return "", fmt.Errorf("URL is too long")
	}
	return out, nil
}

// SortKey orders results by (location, startLine, startColumn), then index, so
// occurrence numbers are deterministic.
func SortResults(items []int, loc func(int) string, line func(int) int, col func(int) int) {
	sort.SliceStable(items, func(a, b int) bool {
		i, j := items[a], items[b]
		if li, lj := loc(i), loc(j); li != lj {
			return li < lj
		}
		if x, y := line(i), line(j); x != y {
			return x < y
		}
		return col(i) < col(j)
	})
}
