package netguard

import (
	"context"
	"net"
	"testing"
)

type fakeResolver map[string][]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, s := range f[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	return out, nil
}

func TestValidateRepoURL(t *testing.T) {
	g := &Guard{}
	ok := []string{
		"https://github.com/org/repo.git", "https://git.example.com:8443/a/b", "ssh://git@host.example/org/repo.git",
		"git@github.com:org/repo.git", "ssh://host.example/repo",
	}
	for _, u := range ok {
		if _, _, err := g.ValidateRepoURL(u); err != nil {
			t.Errorf("%q rejected: %v", u, err)
		}
	}
	bad := []string{
		"", "file:///etc", "/tmp/repo", "./repo", "git://host/x", "http://host/x", "ext::sh -c id", "ftp://h/x",
		"-oProxyCommand=id", "--upload-pack=x", "https://user:pw@host/x", "https://user@host/x", "ssh://u:pw@host/x",
		"https://host/x y", "https://host/x\n", "https://127.0.0.1/x", "https://10.0.0.5/x", "https://192.168.1.1/x",
		"https://169.254.169.254/latest", "https://100.64.0.1/x", "https://[::1]/x", "https://[fd00::1]/x",
		"git@127.0.0.1:x/y", "https://host/x?token=1", "ssh://host", "host.example:path",
	}
	for _, u := range bad {
		if _, _, err := g.ValidateRepoURL(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if _, _, err := g.ValidateRepoURL("https://10.0.0.5/x"); err == nil || err.Error() != ErrBlocked {
		t.Errorf("private literal must give the friendly message, got %v", err)
	}
	// Local paths only with the explicit test switch.
	gl := &Guard{AllowLocalRepos: true}
	for _, u := range []string{"/tmp/repo", "file:///tmp/repo"} {
		if k, _, err := gl.ValidateRepoURL(u); err != nil || k != RepoLocal {
			t.Errorf("%q with AllowLocalRepos: %v %v", u, k, err)
		}
	}
	// Allowed-host list.
	ga := &Guard{GitAllowedHosts: []string{"git.example.com"}}
	if _, _, err := ga.ValidateRepoURL("https://git.example.com/a"); err != nil {
		t.Error(err)
	}
	if _, _, err := ga.ValidateRepoURL("https://evil.example.com/a"); err == nil {
		t.Error("host outside allow list accepted")
	}
}

func TestBlockedIP(t *testing.T) {
	blocked := []string{"127.0.0.1", "127.5.5.5", "::1", "169.254.169.254", "169.254.1.1", "fe80::1", "10.1.2.3", "172.16.0.1", "172.31.255.255",
		"192.168.0.1", "100.64.0.1", "100.127.255.255", "fc00::1", "fd12:3456::1", "0.0.0.0", "100.100.100.200", "224.0.0.1", "::ffff:10.0.0.1", "::ffff:127.0.0.1"}
	for _, s := range blocked {
		if !BlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "93.184.216.34", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111", "11.0.0.1"} {
		if BlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestValidateBaseURLAndResolution(t *testing.T) {
	g := &Guard{Resolver: fakeResolver{"good.example": {"93.184.216.34"}, "rebind.example": {"93.184.216.34", "10.0.0.7"},
		"loop.example": {"127.0.0.1"}, "meta.example": {"169.254.169.254"}, "v6.example": {"fd00::5"}}}
	for _, u := range []string{"https://good.example", "http://good.example:8080/app", "https://good.example/"} {
		if _, err := g.ValidateBaseURL(u); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
	for _, u := range []string{"", "ftp://x", "https://u:p@x.example", "https://x.example/?a=1", "https://x.example/#f", "http://127.0.0.1",
		"http://10.0.0.1", "http://[::1]:80", "http://169.254.169.254/", "https://x.example:99999", "javascript:alert(1)", "https:///x"} {
		if _, err := g.ValidateBaseURL(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	ctx := context.Background()
	if err := g.CheckResolved(ctx, "good.example"); err != nil {
		t.Error(err)
	}
	for _, h := range []string{"rebind.example", "loop.example", "meta.example", "v6.example", "127.0.0.1", "10.9.9.9"} {
		err := g.CheckResolved(ctx, h)
		if err == nil || err.Error() != ErrBlocked {
			t.Errorf("%s: %v", h, err)
		}
	}
	if err := g.CheckResolved(ctx, "nxdomain.example"); err == nil {
		t.Error("unresolvable host accepted")
	}
	// The explicit test switch lifts the policy.
	gt := &Guard{AllowLoopback: true}
	if _, err := gt.ValidateBaseURL("http://127.0.0.1:8080"); err != nil {
		t.Error(err)
	}
	if err := gt.CheckResolved(ctx, "127.0.0.1"); err != nil {
		t.Error(err)
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{"https://Example.com/x": "example.com", "https://example.com:443/x": "example.com",
		"http://example.com:80": "example.com", "http://example.com:8080/a": "example.com:8080"}
	for in, want := range cases {
		if got, _ := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q want %q", in, got, want)
		}
	}
}

func TestAllowPrivateKeepsCloudMetadataBlocked(t *testing.T) {
	g := &Guard{AllowPrivate: true}
	ctx := context.Background()
	for _, h := range []string{"10.1.2.3", "172.16.0.5", "192.168.1.10", "100.64.0.1", "127.0.0.1", "fd12:3456::1", "::1", "169.254.1.1", "169.254.10.20", "fe80::1"} {
		if _, err := g.Resolve(ctx, h); err != nil {
			t.Errorf("%s should be allowed with AllowPrivate: %v", h, err)
		}
		if _, err := g.ValidateBaseURL("http://" + net.JoinHostPort(h, "8080")); err != nil {
			t.Errorf("base_url on %s should be allowed: %v", h, err)
		}
	}
	for _, h := range []string{"169.254.169.254", "169.254.169.253", "169.254.170.2", "100.100.100.200", "fd00:ec2::254",
		"0.0.0.0", "224.0.0.1", "240.0.0.1", "::ffff:169.254.169.254", "metadata.google.internal"} {
		if _, err := g.Resolve(ctx, h); err == nil || err.Error() != ErrBlocked {
			t.Errorf("%s must stay blocked with AllowPrivate: %v", h, err)
		}
	}
	if _, err := g.ValidateBaseURL("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Error("metadata base_url accepted with AllowPrivate")
	}
	if _, _, err := g.ValidateRepoURL("https://10.1.2.3/org/repo.git"); err != nil {
		t.Errorf("private git host should be allowed: %v", err)
	}
	if _, _, err := g.ValidateRepoURL("https://169.254.169.254/org/repo.git"); err == nil {
		t.Error("metadata git host accepted with AllowPrivate")
	}
	// Default policy is unchanged.
	d := &Guard{}
	if _, err := d.Resolve(ctx, "10.1.2.3"); err == nil {
		t.Error("private address accepted by the default policy")
	}
}
