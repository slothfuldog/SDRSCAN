package testutil

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// RealStatusJSON is the output of the real `sdrscan-vuln status --json` (format_version 1) on the
// repository fixture tests/fixtures/vulndb, 8 days after its last update (so stale = true).
const RealStatusJSON = `{
  "advisory_count": 13,
  "age_days": 8,
  "format_version": 1,
  "max_age_days": 7,
  "nvd": {
    "age_days": 8,
    "entries": 4,
    "last_modified": "2026-10-20T00:00:00Z",
    "products": ["cpe:2.3:a:apache:http_server", "cpe:2.3:a:nginx:nginx", "cpe:2.3:a:php:php"],
    "updated_at": "2026-10-20T00:00:00Z"
  },
  "osv": {
    "Go": {"advisories": 2, "age_days": 8, "updated_at": "2026-10-20T00:00:00Z"},
    "Packagist": {"advisories": 4, "age_days": 8, "updated_at": "2026-10-20T00:00:00Z"},
    "crates.io": {"advisories": 1, "age_days": 8, "updated_at": "2026-10-20T00:00:00Z"},
    "npm": {"advisories": 2, "age_days": 8, "updated_at": "2026-10-20T00:00:00Z"}
  },
  "path": "tests/fixtures/vulndb",
  "stale": true,
  "updated_at": "2026-10-20T00:00:00Z"
}`

// FakeVuln describes a stand-in for the `sdrscan-vuln` binary (a small shell script). Tests never
// download CVE data: this script only prints canned status output and simulates an update.
type FakeVuln struct {
	// StatusJSON is printed by `status --json` (see RealStatusJSON for the real shape).
	StatusJSON string
	// StatusExit, when non-zero, makes `status` fail with this code.
	StatusExit int
	// UpdateScript is the shell body of `update` (default: print two lines and succeed).
	UpdateScript string
}

// FakeVulnTool writes the script and returns its path and the path of the file that records every
// call (one line of arguments per call; the environment of the last `update` goes to update.env).
func FakeVulnTool(t testing.TB, f FakeVuln) (bin, callsFile, envFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "sdrscan-vuln")
	callsFile = filepath.Join(dir, "calls.log")
	envFile = filepath.Join(dir, "update.env")
	if f.UpdateScript == "" {
		f.UpdateScript = "echo 'osv: downloading Packagist'; echo 'osv: 3 advisories written'"
	}
	jsonPart := "cat <<'JSON_EOF'\n" + f.StatusJSON + "\nJSON_EOF"
	script := `#!/bin/sh
echo "$@" >> "` + callsFile + `"
cmd="$1"; shift
case "$cmd" in
  status)
    [ ` + strconv.Itoa(f.StatusExit) + ` -ne 0 ] && { echo "status failed" >&2; exit ` + strconv.Itoa(f.StatusExit) + `; }
    ` + jsonPart + `
    ;;
  update)
    env > "` + envFile + `"
    ` + f.UpdateScript + `
    ;;
  *) echo "unknown command" >&2; exit 2 ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, callsFile, envFile
}

// Calls returns the recorded calls of a fake tool, one entry per call.
func Calls(t testing.TB, callsFile string) []string {
	t.Helper()
	b, err := os.ReadFile(callsFile)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}
