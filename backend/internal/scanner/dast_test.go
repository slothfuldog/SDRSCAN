package scanner_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func (r *rig) urlCB(name, base string, confirmed bool) store.Codebase {
	r.t.Helper()
	ctx := context.Background()
	cb, err := r.env.Store.CreateCodebase(ctx, store.NewCodebase{ProjectID: r.proj.ID, Name: name, TargetType: "url", BaseURL: &base, RegisteredBy: &r.adm.ID})
	if err != nil {
		r.t.Fatal(err)
	}
	if confirmed {
		cb, err = r.env.Store.ConfirmDast(ctx, cb.ID, r.adm.ID, "I confirm")
		if err != nil {
			r.t.Fatal(err)
		}
	}
	return cb
}

func target(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Set-Cookie", "sid=SESSIONVALUE123456; Path=/")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/other">x</a></body></html>`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestE2EDastWithRealEngineOnLoopbackTestServer(t *testing.T) {
	e := testutil.RealEngines(t)
	r := newRig(t, rigOpts{
		guard:  &netguard.Guard{AllowLoopback: true, Resolver: testutil.DefaultResolver()},
		runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates},
	})
	srv := target(t)
	cb := r.urlCB("live", srv.URL, true)
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" || sc.Type != "dast" || sc.Coverage != "full" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if sc.Engine == nil || *sc.Engine != "sdrscan-dast" {
		t.Fatalf("engine: %v", sc.Engine)
	}
	fs, total, _ := r.env.Store.ListFindings(context.Background(), store.FindingFilter{CodebaseID: cb.ID, IncludeLow: true}, store.Page{Page: 1, Size: 100})
	if total == 0 {
		t.Fatal("expected passive findings (missing security headers)")
	}
	rules := map[string]bool{}
	for _, f := range fs {
		if f.LocationKind != "url" || f.URL == nil || !strings.HasPrefix(*f.URL, srv.URL) || f.Path != nil || f.StartLine != nil {
			t.Fatalf("DAST finding must have a url location: %+v", f)
		}
		rules[f.RuleID] = true
	}
	if !rules["dast-missing-csp"] {
		t.Fatalf("expected dast-missing-csp among %v", rules)
	}
	// No cookie value in the database, whatever the engine put in the evidence.
	var hits int
	_ = r.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM findings f WHERE f::text LIKE '%SESSIONVALUE123456%'`).Scan(&hits)
	if hits != 0 {
		t.Fatal("cookie value stored")
	}
	cbRow, _ := r.env.Store.GetCodebase(context.Background(), cb.ID)
	if !cbRow.Scanned() || cbRow.Counts() == (store.Counts{}) {
		t.Fatalf("codebase summary: %+v", cbRow.Counts())
	}
	r.assertWorkdirClean()
}

func TestDastPrivateTargetsAreRefusedWithoutTheTestSwitch(t *testing.T) {
	e := testutil.RealEngines(t)
	srv := target(t)
	// 1. Backend policy on: the job fails before the engine runs, with the friendly message.
	r := newRig(t, rigOpts{runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates}})
	cb := r.urlCB("live", srv.URL, true) // inserted directly: bypasses API validation on purpose
	sc := r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "address_not_allowed" || !strings.Contains(logOf(sc), "Private network addresses are not allowed") {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if strings.Contains(logOf(sc), "running sdrscan-dast") {
		t.Fatal("the engine must not be started for a blocked target")
	}
	// 2. Backend policy lifted but the engine told to block private networks: the engine itself refuses (exit 2).
	r2 := newRig(t, rigOpts{
		guard:  &netguard.Guard{AllowLoopback: true, Resolver: testutil.DefaultResolver()},
		runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates},
	})
	r2.env.Runner.Cfg.DastAllowPrivate = false
	r2.env.Runner.Cfg.DastBlockPrivateNetworks = true
	cb2 := r2.urlCB("live", srv.URL, true)
	sc2 := r2.run(r2.enqueue(cb2))
	if sc2.Status != "failed" || codeOf(sc2) != "engine_failed" {
		t.Fatalf("%s %s\n%s", sc2.Status, codeOf(sc2), logOf(sc2))
	}
	r2.assertWorkdirClean()
}

func TestDastJobFailsWhenTargetBecomesPendingWhileQueued(t *testing.T) {
	e := testutil.RealEngines(t)
	r := newRig(t, rigOpts{
		guard:  &netguard.Guard{AllowLoopback: true, Resolver: testutil.DefaultResolver()},
		runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates},
	})
	srv := target(t)
	cb := r.urlCB("live", srv.URL, true)
	sc := r.enqueue(cb)
	// The URL changes while the job waits: back to pending_confirmation.
	if _, err := r.env.Store.UpdateCodebase(context.Background(), cb.ID, map[string]any{
		"base_url": srv.URL + "/v2", "dast_status": "pending_confirmation",
		"dast_confirmed_by": nil, "dast_confirmed_at": nil, "dast_confirmation_text": nil}); err != nil {
		t.Fatal(err)
	}
	got := r.run(sc)
	if got.Status != "failed" || codeOf(got) != "target_not_confirmed" {
		t.Fatalf("%s %s", got.Status, codeOf(got))
	}
}

func TestScheduledDastRechecksOwnerAtRunTime(t *testing.T) {
	e := testutil.RealEngines(t)
	r := newRig(t, rigOpts{
		guard:  &netguard.Guard{AllowLoopback: true, Resolver: testutil.DefaultResolver()},
		runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates},
	})
	ctx := context.Background()
	srv := target(t)
	owner := r.env.CreateUser("owner", "member", true)
	cb := r.urlCB("live", srv.URL, true)
	if _, err := r.env.Store.SetSchedule(ctx, cb.ID, "0 * * * *", owner.ID); err != nil {
		t.Fatal(err)
	}
	sc, err := r.env.Store.CreateJob(ctx, cb.ID, "dast", "schedule", &owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The owner loses DAST access between queueing and running.
	f := false
	if _, _, err := r.env.Store.UpdateUser(ctx, owner.ID, store.UserPatch{CanRunDAST: &f}); err != nil {
		t.Fatal(err)
	}
	got := r.run(sc)
	if got.Status != "failed" || codeOf(got) != "schedule_suspended" {
		t.Fatalf("%s %s\n%s", got.Status, codeOf(got), logOf(got))
	}
}
