package server

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/vault"
)

const (
	matchDomain     = 0
	matchHost       = 1
	matchStartsWith = 2
	matchExact      = 3
	matchRegex      = 4
	matchNever      = 5
)

func parseURL(raw string) *url.URL { return vault.ParseLooseURL(raw) }

// registrableDomain mimics Utils.getDomain (tldts): eTLD+1, or the host for IPs/localhost.
func registrableDomain(raw string) string {
	u := parseURL(raw)
	if u == nil {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || net.ParseIP(h) != nil {
		return h
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return h
	}
	return d
}

// ciphersForURL implements cipherService.getAllDecryptedForUrl for login items.
func ciphersForURL(ciphers []*vault.CipherView, rawURL string, domains *vault.DomainsData) []*vault.CipherView {
	domain := registrableDomain(rawURL)
	eq := map[string]bool{}
	if domain != "" {
		eq[domain] = true
		if domains != nil {
			for _, set := range domains.EquivalentDomains {
				if contains(set, domain) {
					for _, d := range set {
						eq[d] = true
					}
				}
			}
			for _, g := range domains.GlobalEquivalentDomains {
				if !g.Excluded && contains(g.Domains, domain) {
					for _, d := range g.Domains {
						eq[d] = true
					}
				}
			}
		}
	}
	var out []*vault.CipherView
	for _, c := range ciphers {
		if c.IsDeleted() || c.Type != vault.CipherTypeLogin || c.Login == nil {
			continue
		}
		for _, u := range c.Login.URIs {
			if u.URI != nil && uriMatches(*u.URI, u.Match, rawURL, eq) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

func uriMatches(uri string, match *int, target string, eq map[string]bool) bool {
	m := matchDomain
	if match != nil {
		m = *match
	}
	switch m {
	case matchDomain:
		d := registrableDomain(uri)
		return d != "" && eq[d]
	case matchHost:
		a, b := parseURL(uri), parseURL(target)
		return a != nil && b != nil && strings.EqualFold(a.Host, b.Host)
	case matchStartsWith:
		return strings.HasPrefix(target, uri)
	case matchExact:
		return target == uri
	case matchRegex:
		re, err := regexp.Compile("(?i)" + uri)
		return err == nil && re.MatchString(target)
	}
	return false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
