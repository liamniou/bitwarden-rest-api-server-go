package vault

import (
	"net/url"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// SearchIndex holds the pre-normalized fields used by basic search, computed
// once per decrypted cipher so lookups by name don't redo Unicode work.
type SearchIndex struct {
	Name     string
	SubTitle string
	Notes    string
	Hosts    []string
}

// NormalizeSearch lowercases and strips combining diacritics (U+0300-U+036F)
// after NFD decomposition, like normalizeSearchQuery in the clients.
func NormalizeSearch(s string) string {
	s = strings.ToLower(s)
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	d := norm.NFD.String(s)
	var b strings.Builder
	b.Grow(len(d))
	for _, r := range d {
		if r >= 0x300 && r <= 0x36f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ParseLooseURL parses a URI, assuming http:// when no scheme is present.
func ParseLooseURL(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}
	return u
}

// URIHostname returns the hostname part of a login URI.
func URIHostname(raw string) string {
	if u := ParseLooseURL(raw); u != nil {
		return u.Hostname()
	}
	return ""
}

func (c *CipherView) newSearchIndex() *SearchIndex {
	idx := &SearchIndex{Name: NormalizeSearch(c.Name)}
	if sub := c.SubTitle(); sub != "" {
		idx.SubTitle = NormalizeSearch(sub)
	}
	if c.Notes != nil {
		idx.Notes = NormalizeSearch(*c.Notes)
	}
	if c.Type == CipherTypeLogin && c.Login != nil {
		for _, u := range c.Login.URIs {
			if u.URI == nil || *u.URI == "" {
				continue
			}
			if h := URIHostname(*u.URI); h != "" {
				idx.Hosts = append(idx.Hosts, NormalizeSearch(h))
			}
		}
	}
	return idx
}

// Search returns the index built at decrypt time. Views are shared read-only
// snapshots, so a missing index is computed on the fly rather than stored.
func (c *CipherView) Search() *SearchIndex {
	if c.search != nil {
		return c.search
	}
	return c.newSearchIndex()
}
