package generator

import (
	"strings"
	"testing"
	"unicode"
)

func TestWordlist(t *testing.T) {
	if len(Wordlist) != 7776 || Wordlist[0] != "abacus" || Wordlist[7775] != "zoom" {
		t.Fatalf("unexpected wordlist: %d words", len(Wordlist))
	}
}

func count(s string, f func(rune) bool) int {
	n := 0
	for _, r := range s {
		if f(r) {
			n++
		}
	}
	return n
}

func TestPasswordConstraints(t *testing.T) {
	isSpecial := func(r rune) bool { return strings.ContainsRune("!@#$%^&*", r) }
	for i := 0; i < 200; i++ {
		o := Enforce(Options{Type: "password", Length: 20, Uppercase: true, Lowercase: true, Number: true, Special: true, MinNumber: 3, MinSpecial: 2}, nil)
		p := Generate(o)
		if len(p) != 20 || count(p, unicode.IsDigit) < 3 || count(p, isSpecial) < 2 ||
			count(p, unicode.IsUpper) < 1 || count(p, unicode.IsLower) < 1 {
			t.Fatalf("constraint violation: %q", p)
		}
	}
	p := Generate(Enforce(Options{Type: "password", Length: 200, Uppercase: true, Lowercase: true, Number: true}, nil))
	if len(p) != 128 || strings.ContainsAny(p, "lIO01") {
		t.Fatalf("expected 128 chars without ambiguous characters, got %d %q", len(p), p)
	}
}

func TestPassphraseAndPolicy(t *testing.T) {
	o := Enforce(Options{Type: "passphrase", NumWords: 4, WordSeparator: "_", Capitalize: true, IncludeNumber: true}, nil)
	pp := Generate(o)
	words := strings.Split(pp, "_")
	if len(words) != 4 || count(pp, unicode.IsDigit) != 1 {
		t.Fatalf("bad passphrase %q", pp)
	}
	for _, w := range words {
		if !unicode.IsUpper([]rune(w)[0]) {
			t.Fatalf("word not capitalized: %q", pp)
		}
	}
	pol := &Policy{OverridePasswordType: "password", MinLength: 30, UseSpecial: true, SpecialCount: 4}
	o = Enforce(Options{Type: "passphrase", Length: 10, Lowercase: true}, pol)
	if o.Type != "password" || o.Length != 30 || !o.Special || o.MinSpecial != 4 {
		t.Fatalf("policy not applied: %+v", o)
	}
}

func TestFingerprintPhrase(t *testing.T) {
	h := make([]byte, 32)
	if got := strings.Join(FingerprintPhrase(h), "-"); got != "abacus-abacus-abacus-abacus-abacus" {
		t.Fatalf("zero hash phrase = %s", got)
	}
	h[31] = 1
	if got := FingerprintPhrase(h)[0]; got != "abdomen" {
		t.Fatalf("first word = %s", got)
	}
}
