package main

import "testing"

func TestIsLinkedInURL(t *testing.T) {
	good := []string{
		"https://www.linkedin.com/in/robertjgonz/",   // attribution, trailing slash
		"https://www.linkedin.com/in/ada-lovelace-9", // hyphens + digit
		"www.linkedin.com/in/x",                      // scheme-less → https
		"  www.linkedin.com/in/z  ",                  // trimmed
		// inclusive of non-Latin names — raw and percent-encoded UTF-8 both pass
		"https://www.linkedin.com/in/josé",               // accented Latin (raw)
		"https://www.linkedin.com/in/jos%C3%A9",          // accented Latin (%-encoded é)
		"https://www.linkedin.com/in/Müller",             // umlaut (raw)
		"https://www.linkedin.com/in/山田太郎",               // Japanese (raw)
		"https://www.linkedin.com/in/%E5%B1%B1%E7%94%B0", // 山田 (%-encoded UTF-8)
		"https://www.linkedin.com/in/محمد",               // Arabic (raw)
		"https://www.linkedin.com/in/%E7%8E%8B%E4%BC%9F", // 王伟 — Chinese name %-encoded → decodes to letters
	}
	bad := []string{
		"", "not a url",
		"http://www.linkedin.com/in/x",          // plain http rejected (https-only)
		"https://uk.linkedin.com/in/y",          // country subdomain rejected (exact host only)
		"https://www.linkedin.com/company/acme", // not a profile (/in/ only)
		"https://www.linkedin.com/in/u/extra",   // extra path segment past the username
		"https://www.linkedin.com/in/u?utm=x",   // query string
		"https://www.linkedin.com/in/u#frag",    // fragment
		"https://www.linkedin.com/in/bad_name",  // '_' is punctuation, not a letter (LinkedIn forbids it too)
		"https://www.linkedin.com/in/a b",       // space
		"https://www.linkedin.com/in/",          // empty username
		"https://www.linkedin.com/in",           // no username
		"https://www.linkedin.com/",             // no /in/
		"https://linkedin.com.evil.com/in/x",    // spoofed parent domain
		"https://evillinkedin.com/in/x",         // not a subdomain
		"https://linkedin.com@evil.com/in/x",    // userinfo trick → host is evil.com
		"ftp://www.linkedin.com/in/x",           // wrong scheme
		"javascript:alert(1)//linkedin.com/in/x",
		// delimiter / encoding evasion — validated on the decoded path
		"https://www.linkedin.com/in/foo%2Fbar", // %2F → '/' → extra segment
		"https://www.linkedin.com/in/a%252Fb",   // double-encoded → leftover '%' (symbol)
		"https://www.linkedin.com/in/a%00b",     // NUL (control)
		"https://www.linkedin.com/in/%2e%2e",    // '.' (punctuation)
		"https://www.linkedin.com/in/a%09b",     // TAB (control)
		"https://www.linkedin.com/in/a%3Ab",     // %3A → ':' → injection delimiter, rejected
		// dangerous Unicode — letters-adjacent but NOT letters/numbers/marks → rejected
		"https://www.linkedin.com/in/a%E2%80%8Bb", // zero-width space U+200B (format)
		"https://www.linkedin.com/in/a%E2%80%AEb", // RTL override U+202E (format/bidi)
	}
	for _, s := range good {
		if !isLinkedInURL(s) {
			t.Errorf("expected accepted: %q", s)
		}
	}
	for _, s := range bad {
		if isLinkedInURL(s) {
			t.Errorf("expected REJECTED: %q", s)
		}
	}
}
