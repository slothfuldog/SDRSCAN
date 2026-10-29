package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Source is one data source of the database: an OSV ecosystem or NVD.
type Source struct {
	Name       string // "osv" or "nvd"
	Ecosystem  string // OSV ecosystem; "" for NVD
	Advisories int    // advisories (OSV) or entries (NVD)
	UpdatedAt  *time.Time
	AgeDays    *int
	Products   []string // NVD: the curated CPE products
}

// Status is the state of the database as reported by `sdrscan-vuln status --json`.
type Status struct {
	Installed     bool
	AdvisoryCount int
	UpdatedAt     *time.Time
	AgeDays       *int
	MaxAgeDays    int
	Stale         bool // computed by the CLI against MaxAgeDays
	FormatVersion *int
	Sources       []Source
}

// metaFile is the file whose absence means "no database installed" (checked here, so the answer does
// not depend on the language of the tool's error message).
const metaFile = "meta.json"

// Status asks `sdrscan-vuln status --json` about the database. The answer is cached for a few
// seconds (the UI polls while an update runs). A directory without meta.json is reported as not
// installed, without running the tool.
func (m *Manager) Status(ctx context.Context) (*Status, error) {
	if m.cfg.Dir == "" {
		return nil, ErrNotConfigured
	}
	if _, err := os.Stat(filepath.Join(m.cfg.Dir, metaFile)); err != nil && os.IsNotExist(err) {
		return m.notInstalled(), nil
	}
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if !m.cachedAt.IsZero() && time.Since(m.cachedAt) < statusTTL {
		return m.cached, m.cachedEr
	}
	st, err := m.readStatus(ctx)
	m.cached, m.cachedEr, m.cachedAt = st, err, time.Now()
	return st, err
}

func (m *Manager) notInstalled() *Status {
	return &Status{MaxAgeDays: m.maxAgeDays(), Sources: []Source{}}
}

func (m *Manager) maxAgeDays() int {
	d := int(m.cfg.StaleAfter / (24 * time.Hour))
	if d < 1 {
		d = 1
	}
	return d
}

func (m *Manager) invalidateStatus() {
	m.cacheMu.Lock()
	m.cachedAt = time.Time{}
	m.cacheMu.Unlock()
}

func (m *Manager) readStatus(ctx context.Context) (*Status, error) {
	if !m.ToolAvailable() {
		return nil, ErrToolUnavailable
	}
	sctx, cancel := context.WithTimeout(ctx, m.cfg.StatusTimeout)
	defer cancel()
	out, errOut, exit, nf := m.capture(sctx, "status", "--json", "--db", m.cfg.Dir, "--max-age-days", strconv.Itoa(m.maxAgeDays()))
	if nf {
		return nil, ErrToolUnavailable
	}
	if exit != 0 {
		msg := cleanLine(firstLine(errOut))
		if msg == "" {
			msg = fmt.Sprintf("sdrscan-vuln status exited with code %d", exit)
		}
		return nil, fmt.Errorf("%s", msg)
	}
	st, ok := ParseStatusJSON([]byte(out))
	if !ok {
		return nil, fmt.Errorf("sdrscan-vuln status returned output that is not valid JSON")
	}
	if st.MaxAgeDays <= 0 {
		st.MaxAgeDays = m.maxAgeDays()
	}
	return st, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func parseTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

type srcJSON struct {
	Advisories *int     `json:"advisories"`
	Entries    *int     `json:"entries"`
	AgeDays    *int     `json:"age_days"`
	UpdatedAt  string   `json:"updated_at"`
	Products   []string `json:"products"`
}

// ParseStatusJSON reads the output of `sdrscan-vuln status --json` (format_version 1):
//
//	{"advisory_count":13,"age_days":8,"format_version":1,"max_age_days":7,"stale":true,"updated_at":"…Z","path":"…",
//	 "osv":{"Go":{"advisories":2,"age_days":8,"updated_at":"…Z"}, "Packagist":{…}, "crates.io":{…}, "npm":{…}},
//	 "nvd":{"entries":4,"age_days":8,"updated_at":"…Z","last_modified":"…Z","products":["cpe:2.3:a:nginx:nginx"]}}
//
// Unknown keys are ignored; "osv" and "nvd" are absent when that source was never installed.
func ParseStatusJSON(b []byte) (*Status, bool) {
	var d struct {
		AdvisoryCount int                `json:"advisory_count"`
		AgeDays       *int               `json:"age_days"`
		FormatVersion *int               `json:"format_version"`
		MaxAgeDays    *int               `json:"max_age_days"`
		Stale         bool               `json:"stale"`
		UpdatedAt     string             `json:"updated_at"`
		OSV           map[string]srcJSON `json:"osv"`
		NVD           *srcJSON           `json:"nvd"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, false
	}
	st := &Status{AdvisoryCount: d.AdvisoryCount, AgeDays: d.AgeDays, FormatVersion: d.FormatVersion, Stale: d.Stale,
		UpdatedAt: parseTime(d.UpdatedAt), Sources: []Source{}}
	if d.MaxAgeDays != nil {
		st.MaxAgeDays = *d.MaxAgeDays
	}
	eco := make([]string, 0, len(d.OSV))
	for k := range d.OSV {
		eco = append(eco, k)
	}
	sort.Strings(eco)
	for _, k := range eco {
		if len(st.Sources) >= 64 {
			break
		}
		s := d.OSV[k]
		src := Source{Name: "osv", Ecosystem: truncate(k, 64), AgeDays: s.AgeDays, UpdatedAt: parseTime(s.UpdatedAt), Products: []string{}}
		if s.Advisories != nil {
			src.Advisories = *s.Advisories
		}
		st.Sources = append(st.Sources, src)
	}
	if d.NVD != nil {
		src := Source{Name: "nvd", AgeDays: d.NVD.AgeDays, UpdatedAt: parseTime(d.NVD.UpdatedAt), Products: []string{}}
		if d.NVD.Entries != nil {
			src.Advisories = *d.NVD.Entries
		}
		for _, p := range d.NVD.Products {
			if len(src.Products) < 100 {
				src.Products = append(src.Products, truncate(strings.TrimSpace(p), 200))
			}
		}
		st.Sources = append(st.Sources, src)
	}
	st.Installed = st.UpdatedAt != nil || st.AdvisoryCount > 0 || len(st.Sources) > 0
	return st, true
}

func truncate(s string, n int) string {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "")
	}
	return s
}
