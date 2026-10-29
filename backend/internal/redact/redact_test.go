package redact

import (
	"strings"
	"testing"
)

func TestRuleSnippet(t *testing.T) {
	cases := []struct{ in, want string }{
		{`$apiKey = 'sk_live_abcdef123456'`, `$apiKey = '[REDACTED]'`},
		{`define('API_KEY', 'abc123secret')`, `define('API_KEY', '[REDACTED]')`},
		{`$cfg = ['db_pass' => 'hunter2hunter2', 'user' => 'root']`, `$cfg = ['db_pass' => '[REDACTED]', 'user' => '[REDACTED]']`},
		{`$password = "pa" . "ssword1"`, `$password = "[REDACTED]" . "[REDACTED]"`},
		{`$x = trim('shh-secret')`, `$x = trim('[REDACTED]')`},
		{`weird heredoc <<<EOT`, `[REDACTED]`}, // no literal: fail safe
	}
	for _, c := range cases {
		got := RuleSnippet(c.in)
		if got.Text != c.want {
			t.Errorf("RuleSnippet(%q) = %q, want %q", c.in, got.Text, c.want)
		}
		if !got.Changed {
			t.Errorf("RuleSnippet(%q) not flagged changed", c.in)
		}
	}
}

func TestApplyPatterns(t *testing.T) {
	cases := []struct{ in, mustNot string }{
		{"key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----", "MIIBOgIBAAJB"},
		{"token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
		{"slack xoxb-1234567890-abcdefghij", "xoxb-1234567890"},
		{"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
		{"GET /\nAuthorization: Bearer abcdef.ghijkl\n", "abcdef.ghijkl"},
		{"Cookie: sid=abc123xyz; theme=dark", "abc123xyz"},
		{"Set-Cookie: sid=abc123xyz; Path=/; Secure", "abc123xyz"},
		{`api_key: "AbCdEf123456"`, "AbCdEf123456"},
		{`password=supersecretvalue&x=1`, "supersecretvalue"},
	}
	for _, c := range cases {
		got := Apply(c.in)
		if strings.Contains(got.Text, c.mustNot) || !got.Changed {
			t.Errorf("Apply(%q) = %q (changed=%v); still contains %q", c.in, got.Text, got.Changed, c.mustNot)
		}
	}
	if got := Apply("Set-Cookie: sid=abc123xyz; Path=/; Secure"); got.Text != "Set-Cookie: sid=[REDACTED]; Path=/; Secure" {
		t.Errorf("set-cookie attributes lost: %q", got.Text)
	}
	if got := Apply("$h = md5($password);"); got.Changed {
		t.Errorf("code without literal value must not change: %q", got.Text)
	}
	if got := Apply("Header X-Content-Type-Options: nosniff tidak ada."); got.Changed {
		t.Errorf("benign text changed: %q", got.Text)
	}
}
