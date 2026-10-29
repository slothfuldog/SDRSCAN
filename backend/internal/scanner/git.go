package scanner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sdrscan/sdrscan/backend/internal/netguard"
)

var branchRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)

// ValidBranch reports whether name is an acceptable branch name.
func ValidBranch(name string) bool {
	return branchRE.MatchString(name) && !strings.HasPrefix(name, "-") && !strings.Contains(name, "..")
}

// GitCreds carries decrypted credentials for one clone.
type GitCreds struct {
	Kind     string // none | https_token | ssh_key
	Username string
	Secret   string
}

// cloneRequest describes a clone.
type cloneRequest struct {
	url     string
	branch  string
	dir     string // target directory (must not exist)
	workdir string // job work directory (HOME, temp key files)
	creds   GitCreds
}

// gitEnv builds the clean environment for git.
func (r *Runner) gitEnv(workdir string, extra ...string) []string {
	path := "/usr/bin:/bin:/usr/local/bin"
	if r.gitPath != "" {
		path = filepath.Dir(r.gitPath) + ":" + path
	}
	proto := "https:ssh"
	if r.Guard.AllowLocalRepos {
		proto += ":file"
	}
	env := []string{
		"PATH=" + path,
		"HOME=" + workdir,
		"LANG=C.UTF-8",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_ALLOW_PROTOCOL=" + proto,
	}
	return append(env, extra...)
}

// shellQuote single-quotes s for GIT_SSH_COMMAND (the only place git parses a shell string).
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// clone performs the shallow, hook-free clone and returns the commit id.
func (r *Runner) clone(ctx context.Context, req cloneRequest, logf func(string)) (string, error) {
	kind, _, err := r.Guard.ValidateRepoURL(req.url)
	if err != nil {
		return "", fmt.Errorf("repository URL rejected: %w", err)
	}
	if !ValidBranch(req.branch) {
		return "", errors.New("branch name rejected")
	}
	cloneURL := req.url
	var pinArgs []string
	var sshAlias string
	if kind == netguard.RepoLocal {
		if !strings.HasPrefix(cloneURL, "file://") {
			cloneURL = "file://" + cloneURL
		}
	} else if h, port := netguard.RepoHost(req.url); h != "" {
		// Resolve again at job start; every record must pass. The connection is
		// then pinned to a checked address so DNS cannot change in between.
		ips, err := r.Guard.Resolve(ctx, h)
		if err != nil {
			return "", err
		}
		isLiteral := net.ParseIP(strings.Trim(h, "[]")) != nil
		if !isLiteral {
			ip := ips[0].String()
			switch kind {
			case netguard.RepoHTTPS:
				if port == "" {
					port = "443"
				}
				pinArgs = append(pinArgs, "-c", "http.curloptResolve="+h+":"+port+":"+ip)
			case netguard.RepoSSH:
				cloneURL = pinnedSSHURL(req.url, ip)
				sshAlias = h
			}
		}
	}

	var extraEnv []string
	var secrets []string
	switch req.creds.Kind {
	case "https_token":
		if kind != netguard.RepoHTTPS {
			return "", errors.New("https token credentials need an https repository URL")
		}
		askpass := filepath.Join(req.workdir, "askpass.sh")
		script := "#!/bin/sh\ncase \"$1\" in\n  Username*) printf '%s\\n' \"$SDRSCAN_GIT_USERNAME\" ;;\n  *) printf '%s\\n' \"$SDRSCAN_GIT_SECRET\" ;;\nesac\n"
		if err := os.WriteFile(askpass, []byte(script), 0o700); err != nil {
			return "", err
		}
		user := req.creds.Username
		if user == "" {
			user = "x-access-token"
		}
		extraEnv = append(extraEnv, "GIT_ASKPASS="+askpass, "SSH_ASKPASS=", "SDRSCAN_GIT_USERNAME="+user, "SDRSCAN_GIT_SECRET="+req.creds.Secret)
		secrets = append(secrets, req.creds.Secret)
	case "ssh_key":
		if kind != netguard.RepoSSH {
			return "", errors.New("SSH key credentials need an ssh repository URL")
		}
		if r.Cfg.GitKnownHosts == "" {
			return "", errors.New("SSH clone needs SDRSCAN_GIT_KNOWN_HOSTS to be configured")
		}
		keyFile := filepath.Join(req.workdir, "id_key")
		key := req.creds.Secret
		if !strings.HasSuffix(key, "\n") {
			key += "\n"
		}
		if err := os.WriteFile(keyFile, []byte(key), 0o600); err != nil {
			return "", err
		}
		defer os.Remove(keyFile)
		secrets = append(secrets, req.creds.Secret)
		extraEnv = append(extraEnv, "GIT_SSH_COMMAND=ssh -i "+shellQuote(keyFile)+
			" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="+shellQuote(r.Cfg.GitKnownHosts))
	default:
		if kind == netguard.RepoSSH {
			if r.Cfg.GitKnownHosts == "" {
				return "", errors.New("SSH clone needs SDRSCAN_GIT_KNOWN_HOSTS to be configured")
			}
			extraEnv = append(extraEnv, "GIT_SSH_COMMAND=ssh -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="+shellQuote(r.Cfg.GitKnownHosts))
		}
	}

	if sshAlias != "" {
		for i, e := range extraEnv {
			if strings.HasPrefix(e, "GIT_SSH_COMMAND=") {
				extraEnv[i] = e + " -o HostKeyAlias=" + shellQuote(sshAlias)
			}
		}
	}
	args := []string{
		"-c", "protocol.allow=never",
		"-c", "http.followRedirects=false",
		"-c", "protocol.https.allow=always",
		"-c", "protocol.ssh.allow=always",
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.fsmonitor=false",
		"-c", "submodule.recurse=false",
		"-c", "transfer.fsckObjects=true",
	}
	if r.Guard.AllowLocalRepos {
		args = append(args, "-c", "protocol.file.allow=always")
	}
	args = append(args, pinArgs...)
	args = append(args, "clone", "--depth", "1", "--single-branch", "--branch", req.branch, "--no-tags",
		"--no-recurse-submodules", "--", cloneURL, req.dir)

	cctx, cancel := context.WithTimeout(ctx, r.Cfg.CloneTimeout)
	defer cancel()
	res := runProc(cctx, procSpec{bin: r.gitBin(), args: args, env: r.gitEnv(req.workdir, extraEnv...), dir: req.workdir,
		grace: r.Cfg.KillGrace, maxOut: r.Cfg.MaxOutputBytes})
	if res.exitCode != 0 || res.notFound {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if cctx.Err() != nil {
			return "", errors.New("clone timed out")
		}
		msg := Sanitize(lastLines(res.stderr, 5), secrets...)
		if res.notFound {
			msg = "git executable not found"
		}
		return "", fmt.Errorf("git clone failed: %s", msg)
	}

	// Size check (repo_too_large).
	var size int64
	_ = filepath.WalkDir(req.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, ierr := d.Info(); ierr == nil {
				size += info.Size()
			}
		}
		return nil
	})
	if r.Cfg.MaxRepoBytes > 0 && size > r.Cfg.MaxRepoBytes {
		return "", errRepoTooLarge
	}

	head := runProc(ctx, procSpec{bin: r.gitBin(), args: []string{"-C", req.dir, "rev-parse", "HEAD"},
		env: r.gitEnv(req.workdir), dir: req.workdir, grace: r.Cfg.KillGrace, maxOut: 4096})
	ref := strings.TrimSpace(head.stdout)
	if head.exitCode != 0 || len(ref) < 7 {
		return "", errors.New("cannot determine the cloned commit")
	}
	return ref, nil
}

var errRepoTooLarge = errors.New("repository is larger than the size limit")

func (r *Runner) gitBin() string {
	if r.gitPath != "" {
		return r.gitPath
	}
	return "git"
}

// pinnedSSHURL rewrites an ssh repo URL (ssh:// or scp-like) to connect to ip.
func pinnedSSHURL(raw, ip string) string {
	host := ip
	if strings.Contains(ip, ":") {
		host = "[" + ip + "]"
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		user := ""
		if u.User != nil {
			user = u.User.Username() + "@"
		}
		h := host
		if p := u.Port(); p != "" {
			h += ":" + p
		}
		return "ssh://" + user + h + u.EscapedPath()
	}
	// scp-like: user@host:path
	at := strings.Index(raw, "@")
	colon := strings.Index(raw[at+1:], ":") + at + 1
	user, path := raw[:at+1], raw[colon+1:]
	if !strings.HasPrefix(path, "/") {
		path = "/~/" + path
	}
	return "ssh://" + user + host + path
}

// resolveRoot returns the scan root inside the clone, refusing symlinks that
// escape the clone directory.
func resolveRoot(cloneDir, subdirectory string) (string, error) {
	base, err := filepath.EvalSymlinks(cloneDir)
	if err != nil {
		return "", err
	}
	if subdirectory == "" {
		return base, nil
	}
	root, err := filepath.EvalSymlinks(filepath.Join(base, filepath.FromSlash(subdirectory)))
	if err != nil {
		return "", fmt.Errorf("subdirectory %q not found in the repository", subdirectory)
	}
	if root != base && !strings.HasPrefix(root, base+string(os.PathSeparator)) {
		return "", errors.New("subdirectory resolves outside the repository")
	}
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("subdirectory %q is not a directory", subdirectory)
	}
	return root, nil
}
