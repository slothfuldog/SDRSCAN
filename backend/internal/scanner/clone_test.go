package scanner_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func okSarif(t *testing.T) string {
	return fakeEngine(t, "cp '"+writeSarif(t, testutil.Doc{})+"' \"$out\"\nexit 0\n")
}

func TestCloneRefusesDangerousRepoURLsAtRunTime(t *testing.T) {
	// The production guard (no local repos). The URLs are written straight to the
	// database to prove the clone step re-validates what the API would have refused.
	for _, u := range []string{"file:///etc", "/etc", "git://git.example.com/x", "http://git.example.com/x", "ext::sh -c touch /tmp/pwn",
		"--upload-pack=touch /tmp/pwn", "https://user:pw@git.example.com/x", "https://10.1.2.3/x.git", "https://internal.example/x.git"} {
		r := newRig(t, rigOpts{runner: scanner.Config{}})
		r.env.Runner.Cfg.SastBin = okSarif(t)
		cb := r.repoCB("c", u)
		sc := r.run(r.enqueue(cb))
		wantCode := "clone_failed"
		if strings.Contains(u, "internal.example") || strings.Contains(u, "10.1.2.3") {
			wantCode = "address_not_allowed"
		}
		if sc.Status != "failed" || codeOf(sc) != wantCode {
			t.Errorf("%q: %s %s (want %s)\n%s", u, sc.Status, codeOf(sc), wantCode, logOf(sc))
		}
		if wantCode == "address_not_allowed" {
			if !strings.Contains(logOf(sc), "Private network addresses are not allowed") {
				t.Errorf("%q: friendly message missing: %s", u, logOf(sc))
			}
		}
		if strings.Contains(logOf(sc), "user:pw") {
			t.Errorf("credentials leaked into log_tail: %s", logOf(sc))
		}
		r.assertWorkdirClean()
	}
	if _, err := os.Stat("/tmp/pwn"); err == nil {
		t.Fatal("a repo URL executed a command")
	}
}

func TestCloneRejectsBadBranchAtRunTime(t *testing.T) {
	r := newRig(t, rigOpts{guard: local()})
	r.env.Runner.Cfg.SastBin = okSarif(t)
	repo := makeRepo(t, map[string]string{"a.php": "<?php\n"})
	cb := r.repoCB("c", repo)
	if _, err := r.env.Pool.Exec(context.Background(), `UPDATE codebases SET branch = '--upload-pack=x' WHERE id = $1`, cb.ID); err != nil {
		t.Fatal(err)
	}
	sc := r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "clone_failed" || !strings.Contains(logOf(sc), "branch") {
		t.Fatalf("%s %s %s", sc.Status, codeOf(sc), logOf(sc))
	}
	// A branch that does not exist is a plain clone failure.
	_, _ = r.env.Pool.Exec(context.Background(), `UPDATE codebases SET branch = 'nope' WHERE id = $1`, cb.ID)
	sc = r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "clone_failed" {
		t.Fatalf("%s %s", sc.Status, codeOf(sc))
	}
	r.assertWorkdirClean()
}

func TestCloneDoesNotRunHooksAndSkipsSubmodulesAndLFS(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hook-ran")
	hookDir := t.TempDir()
	// An init template with a post-checkout hook: a clone that honoured it would run the hook.
	_ = os.MkdirAll(filepath.Join(hookDir, "hooks"), 0o755)
	_ = os.WriteFile(filepath.Join(hookDir, "hooks", "post-checkout"), []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755)
	t.Setenv("GIT_TEMPLATE_DIR", hookDir)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", hookDir+"/hooks")
	repo := makeRepo(t, map[string]string{"a.php": "<?php\n", ".gitmodules": "[submodule \"x\"]\n\tpath = x\n\turl = file:///does/not/exist\n"})
	r := newRig(t, rigOpts{guard: local()})
	r.env.Runner.Cfg.SastBin = okSarif(t)
	cb := r.repoCB("c", repo)
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a git hook was executed during the clone")
	}
}

// fakeGit records argv and a subset of the environment, prints a message that
// contains the secret to stderr and fails, so we can inspect what the backend
// passed and what ended up in the log.
func fakeGit(t *testing.T, secret string) (bin, rec string) {
	t.Helper()
	dir := t.TempDir()
	rec = filepath.Join(dir, "rec")
	bin = filepath.Join(dir, "git")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + rec + ".argv'\nenv > '" + rec + ".env'\n" +
		"if [ -n \"$GIT_ASKPASS\" ]; then \"$GIT_ASKPASS\" 'Username for x' > '" + rec + ".user'; \"$GIT_ASKPASS\" 'Password for x' > '" + rec + ".pass'; cp \"$GIT_ASKPASS\" '" + rec + ".askpass'; fi\n" +
		"if [ -n \"$GIT_SSH_COMMAND\" ]; then key=$(printf '%s' \"$GIT_SSH_COMMAND\" | sed -n \"s/^ssh -i '\\([^']*\\)'.*/\\1/p\"); echo \"$key\" > '" + rec + ".keypath'; cat \"$key\" > '" + rec + ".keycontent'; ls -l \"$key\" > '" + rec + ".keyperm'; fi\n" +
		"echo 'fatal: could not read from https://oauth2:" + secret + "@git.example.com/x.git token " + secret + "' >&2\nexit 128\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, rec
}

func TestHttpsTokenGoesThroughAskpassNotArgvOrLogs(t *testing.T) {
	const secret = "ghp_TOPSECRETTOKEN0123456789"
	bin, rec := fakeGit(t, secret)
	r := newRig(t, rigOpts{runner: scanner.Config{GitBin: bin}})
	r.env.Runner.Cfg.SastBin = okSarif(t)
	br, url := "main", "https://git.example.com/priv.git"
	enc, _ := r.env.Box.Seal([]byte(secret))
	user := "x-access-token"
	cb, err := r.env.Store.CreateCodebase(context.Background(), store.NewCodebase{ProjectID: r.proj.ID, Name: "p", TargetType: "repo",
		RepoURL: &url, Branch: &br, GitAuthKind: "https_token", GitUsername: &user, GitSecretEnc: enc})
	if err != nil {
		t.Fatal(err)
	}
	sc := r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "clone_failed" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	argv, _ := os.ReadFile(rec + ".argv")
	if bytes.Contains(argv, []byte(secret)) {
		t.Fatalf("the token is in git's arguments:\n%s", argv)
	}
	for _, want := range []string{"protocol.allow=never", "protocol.https.allow=always", "protocol.ssh.allow=always", "core.hooksPath=/dev/null",
		"submodule.recurse=false", "transfer.fsckObjects=true", "--depth\n1", "--single-branch", "--no-tags", "--no-recurse-submodules", "--\nhttps://git.example.com/priv.git",
		"http.followRedirects=false", "http.curloptResolve=git.example.com:443:93.184.216.40"} {
		if !strings.Contains(string(argv), want) {
			t.Errorf("clone arguments lack %q:\n%s", want, argv)
		}
	}
	if strings.Index(string(argv), "--\n") > strings.Index(string(argv), "https://git.example.com/priv.git") {
		t.Error("'--' must precede the URL")
	}
	env, _ := os.ReadFile(rec + ".env")
	for _, want := range []string{"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_LFS_SKIP_SMUDGE=1", "GIT_ASKPASS=", "HOME=" + r.work} {
		if !strings.Contains(string(env), want) {
			t.Errorf("git environment lacks %q", want)
		}
	}
	for _, bad := range []string{"DATABASE_URL", "SDRSCAN_SECRET_KEY"} {
		if strings.Contains(string(env), bad) {
			t.Errorf("git environment contains %s", bad)
		}
	}
	// The askpass helper answers correctly but does not embed the secret.
	u, _ := os.ReadFile(rec + ".user")
	p, _ := os.ReadFile(rec + ".pass")
	if strings.TrimSpace(string(u)) != user || strings.TrimSpace(string(p)) != secret {
		t.Errorf("askpass answers: %q / %q", u, p)
	}
	if script, _ := os.ReadFile(rec + ".askpass"); bytes.Contains(script, []byte(secret)) {
		t.Error("the askpass script embeds the secret")
	}
	// Nothing sensitive in the log, the error or the URL userinfo.
	if l := logOf(sc); strings.Contains(l, secret) || strings.Contains(l, "oauth2:") {
		t.Fatalf("credential in log_tail:\n%s", l)
	}
	r.assertWorkdirClean()
}

func TestSshKeyIsTemporaryAndNeverLogged(t *testing.T) {
	const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END OPENSSH PRIVATE KEY-----"
	bin, rec := fakeGit(t, "KEYSECRET9999")
	known := filepath.Join(t.TempDir(), "known_hosts")
	_ = os.WriteFile(known, []byte("git.example.com ssh-ed25519 AAAA\n"), 0o600)
	r := newRig(t, rigOpts{runner: scanner.Config{GitBin: bin, GitKnownHosts: known}})
	r.env.Runner.Cfg.SastBin = okSarif(t)
	br, url := "main", "git@git.example.com:org/repo.git"
	enc, _ := r.env.Box.Seal([]byte(key))
	cb, err := r.env.Store.CreateCodebase(context.Background(), store.NewCodebase{ProjectID: r.proj.ID, Name: "p", TargetType: "repo",
		RepoURL: &url, Branch: &br, GitAuthKind: "ssh_key", GitSecretEnc: enc})
	if err != nil {
		t.Fatal(err)
	}
	sc := r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "clone_failed" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	env, _ := os.ReadFile(rec + ".env")
	if !strings.Contains(string(env), "StrictHostKeyChecking=yes") || !strings.Contains(string(env), "UserKnownHostsFile='"+known+"'") ||
		!strings.Contains(string(env), "IdentitiesOnly=yes") {
		t.Fatalf("ssh command: %s", env)
	}
	if strings.Contains(string(env), "BEGIN OPENSSH") {
		t.Fatal("the private key is in the environment")
	}
	argv, _ := os.ReadFile(rec + ".argv")
	if strings.Contains(string(argv), "BEGIN OPENSSH") {
		t.Fatal("the private key is in the arguments")
	}
	// The connection is pinned to the checked address; known_hosts is still checked against the real name.
	if !strings.Contains(string(argv), "ssh://git@93.184.216.40/~/org/repo.git") || !strings.Contains(string(env), "HostKeyAlias='git.example.com'") {
		t.Fatalf("ssh pinning:\nargv=%s\nenv=%s", argv, env)
	}
	content, _ := os.ReadFile(rec + ".keycontent")
	if !strings.Contains(string(content), "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("the key file was not available to git: %q", content)
	}
	if perm, _ := os.ReadFile(rec + ".keyperm"); !strings.HasPrefix(string(perm), "-rw-------") {
		t.Fatalf("key file permissions: %s", perm)
	}
	path, _ := os.ReadFile(rec + ".keypath")
	if _, err := os.Stat(strings.TrimSpace(string(path))); err == nil {
		t.Fatal("the temporary key file still exists")
	}
	if strings.Contains(logOf(sc), "BEGIN OPENSSH") || strings.Contains(logOf(sc), "AAAAAAAA") {
		t.Fatal("key material in log_tail")
	}
	r.assertWorkdirClean()
	// ssh clone without a known_hosts file is refused (no trust on first use).
	r2 := newRig(t, rigOpts{runner: scanner.Config{GitBin: bin}})
	r2.env.Runner.Cfg.SastBin = okSarif(t)
	cb2 := r2.repoCB("p", "git@git.example.com:org/repo.git")
	sc2 := r2.run(r2.enqueue(cb2))
	if sc2.Status != "failed" || !strings.Contains(logOf(sc2), "SDRSCAN_GIT_KNOWN_HOSTS") {
		t.Fatalf("%s %s", sc2.Status, logOf(sc2))
	}
}

func TestCredentialThatCannotBeDecryptedFailsCleanly(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.env.Runner.Cfg.SastBin = okSarif(t)
	br, url := "main", "https://git.example.com/priv.git"
	cb, _ := r.env.Store.CreateCodebase(context.Background(), store.NewCodebase{ProjectID: r.proj.ID, Name: "p", TargetType: "repo",
		RepoURL: &url, Branch: &br, GitAuthKind: "https_token", GitSecretEnc: bytes.Repeat([]byte{1}, 64)})
	sc := r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "clone_failed" || !strings.Contains(logOf(sc), "SDRSCAN_SECRET_KEY") {
		t.Fatalf("%s %s %s", sc.Status, codeOf(sc), logOf(sc))
	}
}

func TestRealGitMissingGitBinaryIsReported(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	r := newRig(t, rigOpts{guard: local(), runner: scanner.Config{GitBin: "/nonexistent/git"}})
	r.env.Runner.Cfg.SastBin = okSarif(t)
	repo := makeRepo(t, map[string]string{"a.php": "<?php\n"})
	sc := r.run(r.enqueue(r.repoCB("c", repo)))
	if sc.Status != "failed" || codeOf(sc) != "clone_failed" {
		t.Fatalf("%s %s", sc.Status, codeOf(sc))
	}
}

var _ = netguard.RepoLocal
