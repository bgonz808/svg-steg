package main

import (
	"net/url"
	"strings"
	"unicode"
)

// isLinkedInURL reports whether s is a LinkedIn *profile* URL — strict on STRUCTURE, inclusive
// on NAMES (no one should have to anglicize their name to use this):
//   - scheme: https:// OR scheme-less (bare "linkedin.com/in/x"), treated as https. Plain
//     http:// and every other scheme are rejected.
//   - host: EXACTLY linkedin.com or www.linkedin.com — a 2-entry allow-list. url.Parse
//     extracts the host, so userinfo tricks (linkedin.com@evil.com → host evil.com) and
//     spoofs (linkedin.com.evil.com) are rejected.
//   - path: /in/<username>[/] — no extra segments, no query, no fragment.
//   - username: an allow-list of Unicode LETTERS, NUMBERS, combining MARKS, and '-'. This
//     accepts non-Latin names (山田, José, محمد) — typed raw OR percent-encoded UTF-8 — while
//     still rejecting every delimiter, control char, format char (bidi/zero-width), symbol,
//     and space, because none of those are letters/numbers/marks.
//
// The username is validated against the DECODED path, ranged over as RUNES: percent-encoded
// UTF-8 decodes to the real letters (international names pass), an encoded delimiter decodes
// to that delimiter (rejected), double-encoding leaves a literal '%' (a symbol, rejected),
// and malformed UTF-8 decodes to U+FFFD (a symbol, rejected). An allow-list of letter
// categories is total; a denylist never is.
//
// This is the LinkedIn-only SCOPE for the web/WASM product (enforced in svgstegEncode); the
// core EncodeSVG and the CLI stay general-purpose. (net/url is parse-only; no net symbols.)
func isLinkedInURL(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "https://" + s // bare input is treated as https
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h != "linkedin.com" && h != "www.linkedin.com" {
		return false
	}
	return isLinkedInProfilePath(u.Path)
}

// isLinkedInProfilePath reports whether p is exactly /in/<username> with an optional single
// trailing slash, username = one or more Unicode letters/numbers/marks or '-'. Explicit rune
// allow-list, no regex; inclusive of non-Latin names, exclusive of every delimiter/control.
func isLinkedInProfilePath(p string) bool {
	rest, ok := strings.CutPrefix(p, "/in/")
	if !ok {
		return false
	}
	rest = strings.TrimSuffix(rest, "/") // the single trailing slash LinkedIn appends
	if rest == "" {
		return false // empty username
	}
	for _, r := range rest {
		if !(unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r) || r == '-') {
			return false
		}
	}
	return true
}
