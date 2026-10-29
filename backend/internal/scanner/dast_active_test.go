package scanner_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

// helpOutput runs `<bin> scan --help` and returns its combined output, to detect whether a real
// engine binary already supports a given flag.
func helpOutput(t *testing.T, bin string) string {
	t.Helper()
	out, _ := exec.Command(bin, "scan", "--help").CombinedOutput()
	return string(out)
}

// enqueueActive queues a dast job with the given active flags (bypassing the API's own authorization
// checks, which are tested separately in package httpapi): the runner must still pass --active /
// --active-timing to the engine only when explicitly asked, whatever the codebase's own authorization
// state, and must refuse to run when the engine does not support what was asked.
func (r *rig) enqueueActive(cb store.Codebase, active, timing bool) store.Scan {
	r.t.Helper()
	sc, err := r.env.Store.CreateJob(context.Background(), cb.ID, "dast", "manual", &r.adm.ID, store.JobOptions{Active: active, ActiveTiming: timing})
	if err != nil {
		r.t.Fatal(err)
	}
	return sc
}

// authorizeActive marks active scanning authorized on cb directly (store level), as the HTTP handler
// would, and returns the updated row.
func (r *rig) authorizeActive(cb store.Codebase) store.Codebase {
	r.t.Helper()
	out, err := r.env.Store.AuthorizeActiveScanning(context.Background(), cb.ID, r.adm.ID, "I confirm ... "+cb.Name)
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

const activeFlags = allFlags + " --active --active-timing"

func TestActiveScanPassesFlagsOnlyWhenRequestedAndLogsAuthorization(t *testing.T) {
	rec := t.TempDir()
	r := newRig(t, rigOpts{})
	sarif := dastSarif(t, "m")
	r.env.Runner.Cfg.DastBin = authEngine(t, rec, activeFlags, strings.ReplaceAll(
		"echo 'Ringkasan: 3 pages scanned, 7 active requests sent' >&2\ncp \"$SARIF\" \"$out\"\nexit 1\n", "$SARIF", sarif))
	cb := r.urlCB("live", baseURL, true)
	cb = r.authorizeActive(cb)

	sc := r.run(r.enqueueActive(cb, true, true))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	argv := read(t, filepath.Join(rec, "argv"))
	if !strings.Contains(argv, "--active\n") || !strings.Contains(argv, "--active-timing") {
		t.Errorf("argv must carry --active and --active-timing:\n%s", argv)
	}
	log := logOf(sc)
	if !strings.Contains(log, "active scanning authorized by root on "+time.Now().UTC().Format("2006-01-02")) {
		t.Errorf("log lacks the authorization line:\n%s", log)
	}
	if !strings.Contains(log, "type: boolean/error-based/XSS/open-redirect/header-injection/time-based") {
		t.Errorf("log lacks the active-check kinds (with time-based):\n%s", log)
	}
	if !strings.Contains(log, "7 active requests sent") {
		t.Errorf("log lacks the active-request summary:\n%s", log)
	}
	r.assertWorkdirClean()
}

func TestPassiveScanNeverSendsActiveFlags(t *testing.T) {
	rec := t.TempDir()
	r := newRig(t, rigOpts{})
	sarif := dastSarif(t, "m")
	r.env.Runner.Cfg.DastBin = authEngine(t, rec, activeFlags, "cp \""+sarif+"\" \"$out\"\nexit 1\n")
	cb := r.urlCB("live", baseURL, true)
	cb = r.authorizeActive(cb) // authorized, but this job does not ask for it

	sc := r.run(r.enqueueActive(cb, false, false))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	argv := read(t, filepath.Join(rec, "argv"))
	if strings.Contains(argv, "--active") {
		t.Errorf("a passive job must never pass --active or --active-timing:\n%s", argv)
	}
	if strings.Contains(logOf(sc), "active scanning authorized") {
		t.Errorf("a passive job must not log the active-scanning authorization line:\n%s", logOf(sc))
	}
}

func TestActiveScanTimingWithoutActiveIsNeverSent(t *testing.T) {
	// enqueueActive(cb, false, true) models a bad caller; the runner only ever looks at Active, so
	// ActiveTiming alone must never surface as a flag (the API itself refuses this combination earlier).
	rec := t.TempDir()
	r := newRig(t, rigOpts{})
	sarif := dastSarif(t, "m")
	r.env.Runner.Cfg.DastBin = authEngine(t, rec, activeFlags, "cp \""+sarif+"\" \"$out\"\nexit 1\n")
	cb := r.urlCB("live", baseURL, true)
	cb = r.authorizeActive(cb)

	sc := r.run(r.enqueueActive(cb, false, true))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if strings.Contains(read(t, filepath.Join(rec, "argv")), "--active") {
		t.Error("ActiveTiming without Active must not add any --active* flag")
	}
}

func TestActiveScanFailsWithoutRunningWhenEngineLacksActiveSupport(t *testing.T) {
	rec := t.TempDir()
	r := newRig(t, rigOpts{})
	sarif := dastSarif(t, "m")
	r.env.Runner.Cfg.DastBin = authEngine(t, rec, allFlags, "cp \""+sarif+"\" \"$out\"\nexit 1\n") // no --active in --help
	cb := r.urlCB("live", baseURL, true)
	cb = r.authorizeActive(cb)

	sc := r.run(r.enqueueActive(cb, true, false))
	if sc.Status != "failed" || codeOf(sc) != "engine_unsupported" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if _, err := os.Stat(filepath.Join(rec, "argv")); err == nil {
		t.Fatal("the engine must not run when it does not support --active")
	}
	r.assertWorkdirClean()
}

func TestActiveScanTimingFailsWithoutRunningWhenEngineLacksTimingSupport(t *testing.T) {
	rec := t.TempDir()
	r := newRig(t, rigOpts{})
	sarif := dastSarif(t, "m")
	// Supports --active but not --active-timing.
	r.env.Runner.Cfg.DastBin = authEngine(t, rec, allFlags+" --active", "cp \""+sarif+"\" \"$out\"\nexit 1\n")
	cb := r.urlCB("live", baseURL, true)
	cb = r.authorizeActive(cb)

	sc := r.run(r.enqueueActive(cb, true, true))
	if sc.Status != "failed" || codeOf(sc) != "engine_unsupported" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if _, err := os.Stat(filepath.Join(rec, "argv")); err == nil {
		t.Fatal("the engine must not run when it does not support --active-timing")
	}
}

func TestActiveScanPassesOpenAPISpecURLOnlyWhenActiveAndConfigured(t *testing.T) {
	rec := t.TempDir()
	r := newRig(t, rigOpts{})
	sarif := dastSarif(t, "m")
	r.env.Runner.Cfg.DastBin = authEngine(t, rec, activeFlags+" --openapi-spec", "cp \""+sarif+"\" \"$out\"\nexit 1\n")
	cb := r.urlCB("live", baseURL, true)
	cb = r.authorizeActive(cb)
	spec := baseURL + "/openapi.json"
	if _, err := r.env.Store.UpdateCodebase(context.Background(), cb.ID, map[string]any{"dast_openapi_spec_url": spec}); err != nil {
		t.Fatal(err)
	}
	cb, _ = r.env.Store.GetCodebase(context.Background(), cb.ID)

	// Passive job: never passes --openapi-spec even though it is configured.
	sc := r.run(r.enqueueActive(cb, false, false))
	if sc.Status != "succeeded" || strings.Contains(read(t, filepath.Join(rec, "argv")), "--openapi-spec") {
		t.Fatalf("passive job must not pass --openapi-spec: %s\n%s", sc.Status, read(t, filepath.Join(rec, "argv")))
	}
	// Active job: passes it.
	sc2 := r.run(r.enqueueActive(cb, true, false))
	if sc2.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc2.Status, codeOf(sc2), logOf(sc2))
	}
	argv := read(t, filepath.Join(rec, "argv"))
	if !strings.Contains(argv, "--openapi-spec\n"+spec) {
		t.Errorf("argv must carry --openapi-spec %s:\n%s", spec, argv)
	}
	if !strings.Contains(logOf(sc2), "OpenAPI/Swagger spec: "+spec) {
		t.Errorf("log lacks the OpenAPI spec line:\n%s", logOf(sc2))
	}
}

func TestActiveScanSkipsOpenAPISpecGracefullyWhenEngineLacksTheFlag(t *testing.T) {
	rec := t.TempDir()
	r := newRig(t, rigOpts{})
	sarif := dastSarif(t, "m")
	r.env.Runner.Cfg.DastBin = authEngine(t, rec, activeFlags, "cp \""+sarif+"\" \"$out\"\nexit 1\n") // no --openapi-spec support
	cb := r.urlCB("live", baseURL, true)
	cb = r.authorizeActive(cb)
	spec := baseURL + "/openapi.json"
	if _, err := r.env.Store.UpdateCodebase(context.Background(), cb.ID, map[string]any{"dast_openapi_spec_url": spec}); err != nil {
		t.Fatal(err)
	}
	cb, _ = r.env.Store.GetCodebase(context.Background(), cb.ID)

	sc := r.run(r.enqueueActive(cb, true, false))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if strings.Contains(read(t, filepath.Join(rec, "argv")), "--openapi-spec") {
		t.Error("the engine must not receive --openapi-spec when it does not advertise support for it")
	}
	if !strings.Contains(logOf(sc), "does not support --openapi-spec") {
		t.Errorf("log should explain the spec was not used:\n%s", logOf(sc))
	}
}

// TestE2EActiveScanWithRealEngineWhenSupported runs against the real dist/sdrscan-dast only when it
// already advertises --active (`scan --help`); otherwise it is skipped, since the Rust engine may not
// have implemented active scanning yet.
func TestE2EActiveScanWithRealEngineWhenSupported(t *testing.T) {
	e := testutil.RealEngines(t)
	help := helpOutput(t, e.Dast)
	if !strings.Contains(help, "--active") {
		t.Skip("the installed sdrscan-dast does not support --active yet")
	}
	r := newRig(t, rigOpts{
		guard:  &netguard.Guard{AllowLoopback: true, Resolver: testutil.DefaultResolver()},
		runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates},
	})
	srv := target(t)
	cb := r.urlCB("live", srv.URL, true)
	cb = r.authorizeActive(cb)
	sc := r.run(r.enqueueActive(cb, true, false))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if !strings.Contains(logOf(sc), "active scanning authorized by") {
		t.Errorf("log lacks the active-scanning authorization line:\n%s", logOf(sc))
	}
}
