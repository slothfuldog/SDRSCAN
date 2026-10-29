// Package netguard validates repository and DAST target URLs and rejects
// addresses that must never be contacted (loopback, link-local, cloud metadata).
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Guard holds the URL and network policy.
type Guard struct {
	// AllowLocalRepos permits file:// and absolute local paths as repo_url.
	// Test and local demo only; default false.
	AllowLocalRepos bool
	// AllowLoopback lifts the network policy (loopback, private, link-local) for
	// DAST targets and git hosts. Test and demo only; default false.
	AllowLoopback bool
	// AllowPrivate permits all private networks (loopback, RFC 1918, IPv6 ULA, CGNAT, link-local)
	// for DAST targets and git hosts. Cloud metadata endpoints and other special ranges stay blocked. Operator opt-in (SDRSCAN_ALLOW_PRIVATE_NETWORKS); default false.
	AllowPrivate bool
	// GitAllowedHosts, when non-empty, restricts git hosts (lowercase).
	GitAllowedHosts []string
	// Resolver resolves host names; defaults to net.DefaultResolver.
	Resolver interface {
		LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	}
}

var scpLike = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9._-]*)@([A-Za-z0-9][A-Za-z0-9.-]*):([^\s:-][^\s]*|/[^\s]*)$`)

var metadataIPs = []net.IP{
	net.ParseIP("169.254.169.254"),
	net.ParseIP("169.254.170.2"),
	net.ParseIP("100.100.100.200"),
	net.ParseIP("fd00:ec2::254"),
}

// ErrBlocked is the friendly message for any address the backend refuses to contact.
const ErrBlocked = "Private network addresses are not allowed"

// ErrAddressNotAllowed is returned for any refused address (API code address_not_allowed).
var ErrAddressNotAllowed = errors.New(ErrBlocked)

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// BlockedIP reports whether ip is loopback, link-local, private (RFC 1918,
// IPv6 ULA), carrier-grade NAT (100.64.0.0/10), unspecified, multicast or a
// cloud metadata endpoint.
func BlockedIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		if cgnat.Contains(ip4) {
			return true
		}
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, m := range metadataIPs {
		if ip.Equal(m) {
			return true
		}
	}
	return false
}

// cloudServiceNets are cloud metadata and agent service endpoints that stay blocked
// even when private networks are allowed (they hand out credentials to anyone who can reach them).
var cloudServiceNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"169.254.169.0/24", "169.254.170.0/24", "100.100.100.200/32", "fd00:ec2::/32"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// HardBlockedIP reports addresses that stay blocked even when private networks are
// allowed: cloud metadata and service endpoints (169.254.169.0/24, 169.254.170.0/24,
// 100.100.100.200, fd00:ec2::/32), unspecified, multicast and reserved ranges.
// All private networks (loopback, RFC 1918, CGNAT, IPv6 ULA, link-local) are allowed.
func HardBlockedIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, n := range cloudServiceNets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, m := range metadataIPs {
		if ip.Equal(m) {
			return true
		}
	}
	if ip4 := ip.To4(); ip4 != nil && (ip4[0] == 0 || ip4[0] >= 240) {
		return true
	}
	return false
}

// blocked applies the policy to one address.
func (g *Guard) blocked(ip net.IP) bool {
	switch {
	case g.AllowLoopback:
		return false
	case g.AllowPrivate:
		return HardBlockedIP(ip)
	default:
		return BlockedIP(ip)
	}
}

// metadataHostBlocked reports whether the well-known metadata host names are refused.
// They stay refused when only private networks are allowed.
func (g *Guard) metadataHostBlocked(h string) bool {
	return isMetadataHost(h) && !g.AllowLoopback
}

func hasBadChars(s string) bool {
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// RepoKind classifies a validated repo URL.
type RepoKind string

const (
	RepoHTTPS RepoKind = "https"
	RepoSSH   RepoKind = "ssh"
	RepoLocal RepoKind = "local"
)

// ValidateRepoURL checks a repo URL against the TRD rules and returns its kind
// and host.
func (g *Guard) ValidateRepoURL(raw string) (RepoKind, string, error) {
	if raw == "" {
		return "", "", errors.New("repo_url is required")
	}
	if len(raw) > 2000 {
		return "", "", errors.New("repo_url is too long")
	}
	if strings.HasPrefix(raw, "-") {
		return "", "", errors.New("repo_url must not start with '-'")
	}
	if hasBadChars(raw) {
		return "", "", errors.New("repo_url must not contain whitespace or control characters")
	}
	if g.AllowLocalRepos {
		if strings.HasPrefix(raw, "file://") {
			u, err := url.Parse(raw)
			if err != nil || u.Path == "" {
				return "", "", errors.New("invalid file URL")
			}
			return RepoLocal, "", nil
		}
		if filepath.IsAbs(raw) {
			return RepoLocal, "", nil
		}
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "::") && !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "ssh://") {
		return "", "", errors.New("transport helpers such as ext:: are not allowed")
	}
	if m := scpLike.FindStringSubmatch(raw); m != nil && !strings.Contains(raw, "://") {
		return g.finish(RepoSSH, strings.ToLower(m[2]))
	}
	if !strings.Contains(raw, "://") {
		return "", "", errors.New("repo_url must be https://host/path, ssh://host/path or git@host:path")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", errors.New("repo_url is not a valid URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		if u.User != nil {
			return "", "", errors.New("repo_url must not contain credentials; use the credential fields")
		}
		if u.Host == "" || u.Hostname() == "" {
			return "", "", errors.New("repo_url has no host")
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return "", "", errors.New("repo_url must not contain a query or fragment")
		}
		return g.finish(RepoHTTPS, strings.ToLower(u.Hostname()))
	case "ssh":
		if u.User != nil {
			if _, hasPw := u.User.Password(); hasPw {
				return "", "", errors.New("repo_url must not contain a password")
			}
		}
		if u.Hostname() == "" || u.Path == "" || u.Path == "/" {
			return "", "", errors.New("ssh repo_url needs a host and a path")
		}
		return g.finish(RepoSSH, strings.ToLower(u.Hostname()))
	default:
		return "", "", fmt.Errorf("scheme %q is not allowed for repo_url (only https and ssh)", u.Scheme)
	}
}

func isMetadataHost(h string) bool {
	h = strings.TrimSuffix(strings.ToLower(strings.Trim(h, "[]")), ".")
	return h == "metadata.google.internal" || h == "metadata"
}

func (g *Guard) finish(kind RepoKind, host string) (RepoKind, string, error) {
	if g.metadataHostBlocked(host) && !g.AllowLocalRepos {
		return "", "", ErrAddressNotAllowed
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && g.blocked(ip) && !g.AllowLocalRepos {
		return "", "", ErrAddressNotAllowed
	}
	if len(g.GitAllowedHosts) > 0 {
		ok := false
		for _, h := range g.GitAllowedHosts {
			if strings.EqualFold(h, host) {
				ok = true
				break
			}
		}
		if !ok {
			return "", "", fmt.Errorf("git host %q is not in the allowed list", host)
		}
	}
	return kind, host, nil
}

// ValidateBaseURL checks a DAST base URL and returns it normalised (trimmed;
// trailing slash on an empty path is kept as-is).
func (g *Guard) ValidateBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("base_url is required")
	}
	if len(raw) > 2000 {
		return "", errors.New("base_url is too long")
	}
	if hasBadChars(raw) {
		return "", errors.New("base_url must not contain whitespace or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("base_url is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("base_url must use http or https")
	}
	if u.User != nil {
		return "", errors.New("base_url must not contain credentials")
	}
	if u.Hostname() == "" {
		return "", errors.New("base_url has no host")
	}
	if u.RawQuery != "" || u.Fragment != "" || strings.Contains(raw, "?") || strings.Contains(raw, "#") {
		return "", errors.New("base_url must not contain a query or fragment")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("base_url has an invalid port")
		}
	}
	if g.metadataHostBlocked(u.Hostname()) {
		return "", ErrAddressNotAllowed
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && g.blocked(ip) {
		return "", ErrAddressNotAllowed
	}
	return raw, nil
}

// Resolve resolves host and returns its addresses. Every address must pass the
// policy (one forbidden record rejects the host) unless AllowLoopback is set.
func (g *Guard) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.Trim(host, "[]")
	if g.metadataHostBlocked(host) {
		return nil, ErrAddressNotAllowed
	}
	if ip := net.ParseIP(host); ip != nil {
		if g.blocked(ip) {
			return nil, ErrAddressNotAllowed
		}
		return []net.IP{ip}, nil
	}
	res := g.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	addrs, err := res.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("cannot resolve %s", host)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if g.blocked(a.IP) {
			return nil, ErrAddressNotAllowed
		}
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// CheckResolved is Resolve without the addresses.
func (g *Guard) CheckResolved(ctx context.Context, host string) error {
	_, err := g.Resolve(ctx, host)
	return err
}

// RepoHost returns the host of a repo URL (https, ssh:// or scp-like) and its port ("" = default).
func RepoHost(raw string) (host, port string) {
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", ""
		}
		return u.Hostname(), u.Port()
	}
	if i := strings.Index(raw, "@"); i >= 0 {
		rest := raw[i+1:]
		if j := strings.Index(rest, ":"); j >= 0 {
			return rest[:j], ""
		}
	}
	return "", ""
}

// HostOf returns host[:port] of a URL in lowercase with default ports removed.
func HostOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	h := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" || (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		return h, nil
	}
	return h + ":" + port, nil
}
