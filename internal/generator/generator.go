// Package generator implements Bitwarden's password, passphrase and
// fingerprint-phrase generation.
package generator

import (
	"crypto/rand"
	_ "embed"
	"math/big"
	"strings"
	"unicode"
)

// EFF large wordlist (CC BY 3.0 US, https://www.eff.org/dice).
//
//go:embed eff_large_wordlist.txt
var wordlistRaw string

var Wordlist = strings.Fields(wordlistRaw)

// Options mirrors PasswordGeneratorOptions as assembled by `bw generate`.
type Options struct {
	Type          string // "password" or "passphrase"
	Length        int
	Uppercase     bool
	Lowercase     bool
	Number        bool
	Special       bool
	MinUppercase  int
	MinLowercase  int
	MinNumber     int
	MinSpecial    int
	Ambiguous     bool // true = include ambiguous characters
	NumWords      int
	WordSeparator string
	Capitalize    bool
	IncludeNumber bool
}

// Policy is the merged password generator policy of all applicable organizations.
type Policy struct {
	OverridePasswordType string
	MinLength            int
	UseUppercase         bool
	UseLowercase         bool
	UseNumbers           bool
	NumberCount          int
	UseSpecial           bool
	SpecialCount         int
	MinNumberWords       int
	Capitalize           bool
	IncludeNumber        bool
}

func (p *Policy) InEffect() bool {
	return p != nil && (p.OverridePasswordType != "" || p.MinLength > 0 || p.UseUppercase || p.UseLowercase ||
		p.UseNumbers || p.NumberCount > 0 || p.UseSpecial || p.SpecialCount > 0 || p.MinNumberWords > 0 ||
		p.Capitalize || p.IncludeNumber)
}

func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}

func fit(v, min, max int) int {
	if v > max {
		v = max
	}
	if v < min {
		v = min
	}
	return v
}

// Enforce applies policy and sanitization like enforcePasswordGeneratorPoliciesOnOptions.
func Enforce(o Options, p *Policy) Options {
	if p == nil {
		p = &Policy{}
	}
	if p.InEffect() && p.OverridePasswordType != "" {
		o.Type = p.OverridePasswordType
	}
	if o.Type == "" {
		o.Type = "password"
	}
	if o.Type == "password" {
		lenMin := 5
		if p.MinLength > lenMin {
			lenMin = p.MinLength
		}
		digitsMin, specialMin := 0, 0
		if p.NumberCount > 0 {
			digitsMin = p.NumberCount
		}
		if p.SpecialCount > 0 {
			specialMin = p.SpecialCount
		}
		o.Uppercase = p.UseUppercase || o.Uppercase
		o.Lowercase = p.UseLowercase || o.Lowercase
		o.Number = p.UseNumbers || o.Number || o.MinNumber > 0
		o.Special = p.UseSpecial || o.Special || o.MinSpecial > 0
		o.Length = fit(o.Length, lenMin, 128)
		o.MinNumber = fit(o.MinNumber, digitsMin, 9)
		o.MinSpecial = fit(o.MinSpecial, specialMin, 9)

		cascade := func(enabled bool, value int) (bool, int) {
			if !enabled {
				return false, 0
			}
			if value <= 0 {
				value = 1
			}
			return true, value
		}
		o.Lowercase, o.MinLowercase = cascade(o.Lowercase, o.MinLowercase)
		o.Uppercase, o.MinUppercase = cascade(o.Uppercase, o.MinUppercase)
		o.Number, o.MinNumber = cascade(o.Number, o.MinNumber)
		o.Special, o.MinSpecial = cascade(o.Special, o.MinSpecial)
		minLen := o.MinLowercase + o.MinUppercase + o.MinNumber + o.MinSpecial
		if minLen < lenMin {
			minLen = lenMin
		}
		if o.Length < minLen {
			o.Length = minLen
		}
	} else {
		wordsMin := 3
		if p.MinNumberWords > wordsMin {
			wordsMin = p.MinNumberWords
		}
		o.Capitalize = p.Capitalize || o.Capitalize
		o.IncludeNumber = p.IncludeNumber || o.IncludeNumber
		if o.NumWords == 0 {
			o.NumWords = wordsMin
		}
		o.NumWords = fit(o.NumWords, wordsMin, 20)
		if o.WordSeparator != "" {
			o.WordSeparator = string([]rune(o.WordSeparator)[0])
		}
	}
	return o
}

// Generate produces a password or passphrase.
func Generate(o Options) string {
	if o.Type == "passphrase" {
		return passphrase(o)
	}
	return password(o)
}

func password(o Options) string {
	lower := "abcdefghijkmnopqrstuvwxyz"
	upper := "ABCDEFGHJKLMNPQRSTUVWXYZ"
	number := "23456789"
	special := "!@#$%^&*"
	if o.Ambiguous {
		lower += "l"
		upper += "IO"
		number += "01"
	}
	var positions []byte
	add := func(c byte, n int) {
		for i := 0; i < n; i++ {
			positions = append(positions, c)
		}
	}
	if o.Lowercase {
		add('l', o.MinLowercase)
	}
	if o.Uppercase {
		add('u', o.MinUppercase)
	}
	if o.Number {
		add('n', o.MinNumber)
	}
	if o.Special {
		add('s', o.MinSpecial)
	}
	for len(positions) < o.Length {
		positions = append(positions, 'a')
	}
	for i := len(positions) - 1; i > 0; i-- {
		j := randInt(i + 1)
		positions[i], positions[j] = positions[j], positions[i]
	}
	all := ""
	if o.Lowercase {
		all += lower
	}
	if o.Uppercase {
		all += upper
	}
	if o.Number {
		all += number
	}
	if o.Special {
		all += special
	}
	var sb strings.Builder
	for _, p := range positions {
		set := all
		switch p {
		case 'l':
			set = lower
		case 'u':
			set = upper
		case 'n':
			set = number
		case 's':
			set = special
		}
		if set == "" {
			continue
		}
		sb.WriteByte(set[randInt(len(set))])
	}
	return sb.String()
}

func passphrase(o Options) string {
	n := o.NumWords
	if n < 3 {
		n = 3
	}
	words := make([]string, n)
	for i := range words {
		w := Wordlist[randInt(len(Wordlist))]
		if o.Capitalize {
			r := []rune(w)
			r[0] = unicode.ToUpper(r[0])
			w = string(r)
		}
		words[i] = w
	}
	if o.IncludeNumber {
		i := randInt(n)
		words[i] += string(rune('0' + randInt(10)))
	}
	return strings.Join(words, o.WordSeparator)
}

// FingerprintPhrase implements the legacy hashPhrase over a 32-byte hash.
func FingerprintPhrase(hash []byte) []string {
	num := new(big.Int).SetBytes(hash)
	size := big.NewInt(int64(len(Wordlist)))
	mod := new(big.Int)
	out := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		num.DivMod(num, size, mod)
		out = append(out, Wordlist[mod.Int64()])
	}
	return out
}
