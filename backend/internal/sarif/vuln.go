package sarif

import (
	"encoding/json"
	"math"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Limits of the stored vulnerability object. Anything outside them is dropped
// field by field; the finding itself is never rejected because of it.
const (
	MaxVulnerabilityBytes = 64 * 1024
	MaxVulnIDs            = 20
	MaxFixedVersions      = 20
	MaxReferences         = 5
	maxVulnText           = 200
	maxVulnURL            = 2048
	maxVulnVector         = 200
)

// Vulnerability is the validated, normalised properties.vulnerability of a
// result (a CVE / advisory finding). It is stored as JSONB and returned as is
// by the API; every key is always present.
type Vulnerability struct {
	IDs           []string     `json:"ids"`
	Package       *VulnPackage `json:"package"`
	FixedVersions []string     `json:"fixed_versions"`
	Source        *string      `json:"source"`
	References    []string     `json:"references"`
	CVSS          *VulnCVSS    `json:"cvss"`
	Confidence    *string      `json:"confidence"`
	Scope         *string      `json:"scope"`
}

// VulnPackage is {ecosystem,name,version} for a dependency (SCA) or
// {product,version} for a product detected on a running target (DAST).
type VulnPackage struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
}

// VulnCVSS is the base score (0-10) and, when present, the vector string.
type VulnCVSS struct {
	Score  float64 `json:"score"`
	Vector *string `json:"vector"`
}

var (
	advisoryShape = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{1,15}(-[A-Za-z0-9_.]{1,40}){1,4}$`)
	cveStrict     = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	ghsaStrict    = regexp.MustCompile(`^GHSA(-[0-9a-z]{4}){3}$`) // real ids avoid 0/1/i/l/o/u, but be liberal in what is stored; the UI only links the strict alphabet
	vectorShape   = regexp.MustCompile(`^[A-Za-z0-9:/._-]+$`)
)

// NormalizeAdvisoryID validates an advisory identifier (CVE, GHSA or an OSV id
// such as RUSTSEC-2021-0001, GO-2021-0001) and returns its canonical spelling:
// upper case, except the random part of a GHSA id (lower case) and the part after the prefix of other ids (kept).
func NormalizeAdvisoryID(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 || !advisoryShape.MatchString(s) {
		return "", false
	}
	up := strings.ToUpper(s)
	switch {
	case strings.HasPrefix(up, "CVE-"):
		if !cveStrict.MatchString(up) {
			return "", false
		}
		return up, true
	case strings.HasPrefix(up, "GHSA-"):
		g := "GHSA-" + strings.ToLower(up[5:])
		if !ghsaStrict.MatchString(g) {
			return "", false
		}
		return g, true
	}
	// Other advisory ids (RUSTSEC-, GO-, PYSEC-, PKSA-, ...): the prefix is upper case, the rest is kept
	// as the source wrote it (some ecosystems use a lower-case random part).
	i := strings.IndexByte(s, '-')
	return strings.ToUpper(s[:i]) + s[i:], true
}

// cleanText returns s trimmed when it is printable text of at most max
// characters (no control characters), else "", false.
func cleanText(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > max || !utf8.ValidString(s) {
		return "", false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
			return "", false
		}
	}
	return s, true
}

// SafeReference reports whether raw is an http(s) URL that is safe to show as a link target.
func SafeReference(raw string) (string, bool) {
	s, ok := cleanText(raw, maxVulnURL)
	if !ok || strings.ContainsAny(s, " \t<>\"'`\\") {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", false
	}
	return s, true
}

// stringItems returns the string elements of a JSON array (other elements, or a value that is
// not an array, yield nothing) and looks at no more than 200 elements.
func stringItems(raw json.RawMessage) []string {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil
	}
	if len(items) > 200 {
		items = items[:200]
	}
	var out []string
	for _, it := range items {
		var s string
		if json.Unmarshal(it, &s) == nil {
			out = append(out, s)
		}
	}
	return out
}

// ParseVulnerability validates properties.vulnerability of a result whose
// ruleId is ruleID. ok is false when the property is unusable as a whole (not
// an object, too large, or no valid advisory id): the caller then stores a
// plain code finding. Invalid single fields are dropped.
func ParseVulnerability(raw json.RawMessage, ruleID string) (*Vulnerability, bool) {
	if len(raw) == 0 || len(raw) > MaxVulnerabilityBytes {
		return nil, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, false
	}
	v := &Vulnerability{IDs: []string{}, FixedVersions: []string{}, References: []string{}}

	seen := map[string]bool{}
	for _, id := range stringItems(obj["ids"]) {
		if n, ok := NormalizeAdvisoryID(id); ok && !seen[n] && len(v.IDs) < MaxVulnIDs {
			seen[n] = true
			v.IDs = append(v.IDs, n)
		}
	}
	if len(v.IDs) == 0 {
		// Fall back to the rule id, which is the CVE / advisory id for these findings. Only an id that
		// is already in canonical form counts, so an ordinary code rule id never becomes an advisory.
		n, ok := NormalizeAdvisoryID(ruleID)
		if !ok || n != strings.TrimSpace(ruleID) {
			return nil, false
		}
		v.IDs = []string{n}
	}

	var pk struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Product   string `json:"product"`
		Version   string `json:"version"`
	}
	if json.Unmarshal(obj["package"], &pk) == nil {
		p := VulnPackage{}
		p.Ecosystem, _ = cleanText(pk.Ecosystem, 64)
		p.Name, _ = cleanText(pk.Name, 214)
		p.Product, _ = cleanText(pk.Product, maxVulnText)
		p.Version, _ = cleanText(pk.Version, 100)
		if p.Name != "" || p.Product != "" {
			v.Package = &p
		}
	}

	for _, f := range stringItems(obj["fixed_versions"]) {
		if s, ok := cleanText(f, 100); ok && len(v.FixedVersions) < MaxFixedVersions {
			v.FixedVersions = append(v.FixedVersions, s)
		}
	}

	var src string
	if json.Unmarshal(obj["source"], &src) == nil {
		if s := strings.ToLower(strings.TrimSpace(src)); s == "osv" || s == "nvd" {
			v.Source = &s
		}
	}

	for _, r := range stringItems(obj["references"]) {
		if len(v.References) >= MaxReferences {
			break
		}
		if s, ok := SafeReference(r); ok {
			v.References = append(v.References, s)
		}
	}

	var cv struct {
		Score  *float64 `json:"score"`
		Vector *string  `json:"vector"`
	}
	if json.Unmarshal(obj["cvss"], &cv) == nil && cv.Score != nil && !math.IsNaN(*cv.Score) && *cv.Score >= 0 && *cv.Score <= 10 {
		c := &VulnCVSS{Score: math.Round(*cv.Score*10) / 10}
		if cv.Vector != nil {
			if s, ok := cleanText(*cv.Vector, maxVulnVector); ok && vectorShape.MatchString(s) {
				c.Vector = &s
			}
		}
		v.CVSS = c
	}

	var conf string
	if json.Unmarshal(obj["confidence"], &conf) == nil {
		if s := strings.ToLower(strings.TrimSpace(conf)); s == "high" || s == "low" {
			v.Confidence = &s
		}
	}
	var scope string
	if json.Unmarshal(obj["scope"], &scope) == nil {
		if s := strings.ToLower(strings.TrimSpace(scope)); s == "runtime" || s == "dev" {
			v.Scope = &s
		}
	}
	return v, true
}
