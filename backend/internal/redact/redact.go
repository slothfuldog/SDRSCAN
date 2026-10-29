// Package redact masks secret values in snippets and messages before they are
// stored. Layer 1 is rule driven (hard-coded secret rules), layer 2 is pattern
// driven and applies to every finding. Both run in memory at ingest time.
package redact

import (
	"regexp"
	"strings"
)

// Mask replaces a secret value.
const Mask = "[REDACTED]"

var (
	reAWS    = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	rePEM    = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	reGH     = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`)
	reSlack  = regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)
	reJWT    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)
	reAuth   = regexp.MustCompile(`(?im)^(\s*Authorization\s*:[ \t]*)(.*)$`)
	reCookie = regexp.MustCompile(`(?im)^(\s*Cookie\s*:[ \t]*)(.*)$`)
	reSetCk  = regexp.MustCompile(`(?im)^(\s*Set-Cookie\s*:[ \t]*)([^=\r\n;]+=)([^;\r\n]*)`)
	// name = value pairs; the value is a quoted string or a bare token of 8+
	// characters that does not look like code ($var, call()).
	rePair = regexp.MustCompile(`(?i)(\b[A-Za-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|token)[A-Za-z0-9_-]*["']?\s*[:=]>?\s*)(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([A-Za-z0-9_\-./+=~]{8,})(?:[^A-Za-z0-9_\-./+=~(]|$))`)
)

// Result is a redaction outcome.
type Result struct {
	Text    string
	Changed bool
}

// Apply runs the pattern layer (layer 2) over text.
func Apply(text string) Result {
	out := text
	out = rePEM.ReplaceAllString(out, Mask)
	out = reAWS.ReplaceAllString(out, Mask)
	out = reGH.ReplaceAllString(out, Mask)
	out = reSlack.ReplaceAllString(out, Mask)
	out = reJWT.ReplaceAllString(out, Mask)
	out = reAuth.ReplaceAllStringFunc(out, func(m string) string {
		sub := reAuth.FindStringSubmatch(m)
		if v := strings.TrimSpace(sub[2]); v == "" || v == Mask {
			return m
		}
		return sub[1] + Mask
	})
	out = reCookie.ReplaceAllStringFunc(out, func(m string) string {
		sub := reCookie.FindStringSubmatch(m)
		parts := strings.Split(sub[2], ";")
		for i, p := range parts {
			if eq := strings.Index(p, "="); eq >= 0 {
				v := strings.TrimSpace(p[eq+1:])
				if v != "" && v != Mask {
					parts[i] = p[:eq+1] + Mask
				}
			}
		}
		return sub[1] + strings.Join(parts, ";")
	})
	out = reSetCk.ReplaceAllStringFunc(out, func(m string) string {
		sub := reSetCk.FindStringSubmatch(m)
		if strings.TrimSpace(sub[3]) == "" || strings.TrimSpace(sub[3]) == Mask {
			return m
		}
		return sub[1] + sub[2] + Mask
	})
	out = rePair.ReplaceAllStringFunc(out, func(m string) string {
		sub := rePair.FindStringSubmatchIndex(m)
		// groups: 1 prefix, 2 dq, 3 sq, 4 bare
		prefix := m[sub[2]:sub[3]]
		switch {
		case sub[4] >= 0:
			if m[sub[4]:sub[5]] == Mask || m[sub[4]:sub[5]] == "" {
				return m
			}
			return prefix + `"` + Mask + `"`
		case sub[6] >= 0:
			if m[sub[6]:sub[7]] == Mask || m[sub[6]:sub[7]] == "" {
				return m
			}
			return prefix + `'` + Mask + `'`
		case sub[8] >= 0:
			val := m[sub[8]:sub[9]]
			if strings.HasPrefix(val, "[REDACTED") {
				return m
			}
			return prefix + Mask + m[sub[9]:]
		}
		return m
	})
	return Result{Text: out, Changed: out != text}
}

// literal is a quoted string literal located in code.
type literal struct {
	start, end int // content range (inside the quotes)
	quote      byte
}

// scanLiterals finds '...' and "..." literals honouring backslash escapes.
func scanLiterals(s string) []literal {
	var out []literal
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\'' && c != '"' {
			continue
		}
		j := i + 1
		for j < len(s) {
			if s[j] == '\\' {
				j += 2
				continue
			}
			if s[j] == c {
				break
			}
			j++
		}
		if j >= len(s) { // unterminated: treat the rest as the literal
			out = append(out, literal{start: i + 1, end: len(s), quote: c})
			break
		}
		out = append(out, literal{start: i + 1, end: j, quote: c})
		i = j
	}
	return out
}

func prevSignificant(s string, pos int) string {
	// pos is the index of the opening quote; return the text before it, trimmed.
	return strings.TrimRight(s[:pos], " \t\r\n")
}

func nextSignificant(s string, pos int) string {
	return strings.TrimLeft(s[pos:], " \t\r\n")
}

// RuleSnippet applies layer 1 to a snippet of a secret rule: literal values
// after '=', '=>' or ',' are masked while variable and key names stay visible.
// The last operator in the snippet decides the tail that is masked entirely;
// earlier literals are masked when they are values (follow an operator and are
// not array keys). When no literal is recognised the whole snippet is masked
// (fail safe).
func RuleSnippet(snippet string) Result {
	if strings.TrimSpace(snippet) == "" {
		return Result{Text: snippet}
	}
	lits := scanLiterals(snippet)
	if len(lits) == 0 {
		return Result{Text: Mask, Changed: true}
	}
	lastOp := -1
	for _, op := range []string{"=>", "=", ","} {
		if i := strings.LastIndex(snippet, op); i > lastOp {
			lastOp = i
		}
	}
	var b strings.Builder
	cursor := 0
	changed := false
	for _, l := range lits {
		openPos := l.start - 1
		mask := false
		switch {
		case lastOp < 0:
			mask = true // no operator recognised: mask every literal
		case openPos > lastOp:
			mask = true // in the tail after the last operator
		default:
			prev := prevSignificant(snippet, openPos)
			isValue := strings.HasSuffix(prev, "=") || strings.HasSuffix(prev, "=>") || strings.HasSuffix(prev, ",") || strings.HasSuffix(prev, ".")
			next := nextSignificant(snippet, l.end+1)
			isKey := strings.HasPrefix(next, "=>")
			mask = isValue && !isKey
		}
		if !mask {
			continue
		}
		if l.end-l.start == 0 || snippet[l.start:l.end] == Mask {
			continue
		}
		b.WriteString(snippet[cursor:l.start])
		b.WriteString(Mask)
		cursor = l.end
		changed = true
	}
	b.WriteString(snippet[cursor:])
	if !changed {
		return Result{Text: snippet}
	}
	return Result{Text: b.String(), Changed: true}
}

// RuleMessage masks quoted literals in a message of a secret rule (a message
// without literals is returned unchanged).
func RuleMessage(msg string) Result {
	lits := scanLiterals(msg)
	if len(lits) == 0 {
		return Result{Text: msg}
	}
	var b strings.Builder
	cursor := 0
	changed := false
	for _, l := range lits {
		if l.end-l.start == 0 || msg[l.start:l.end] == Mask {
			continue
		}
		b.WriteString(msg[cursor:l.start])
		b.WriteString(Mask)
		cursor = l.end
		changed = true
	}
	b.WriteString(msg[cursor:])
	return Result{Text: b.String(), Changed: changed}
}

// Snippet applies layer 1 (when secretRule) then layer 2.
func Snippet(snippet string, secretRule bool) Result {
	changed := false
	if secretRule {
		r := RuleSnippet(snippet)
		snippet, changed = r.Text, r.Changed
	}
	r2 := Apply(snippet)
	return Result{Text: r2.Text, Changed: changed || r2.Changed}
}

// Message applies layer 1 (when secretRule) then layer 2.
func Message(msg string, secretRule bool) Result {
	changed := false
	if secretRule {
		r := RuleMessage(msg)
		msg, changed = r.Text, r.Changed
	}
	r2 := Apply(msg)
	return Result{Text: r2.Text, Changed: changed || r2.Changed}
}
