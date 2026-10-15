package server

import (
	"testing"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/vault"
)

func login(name, uri string, match *int) *vault.CipherView {
	return &vault.CipherView{Name: name, Type: vault.CipherTypeLogin,
		Login: &vault.LoginView{URIs: []vault.LoginURIView{{URI: &uri, Match: match}}}}
}

func TestCiphersForURL(t *testing.T) {
	host, starts, exact, never, regex := 1, 2, 3, 5, 4
	ciphers := []*vault.CipherView{
		login("domain", "https://accounts.google.com/login", nil),
		login("equivalent", "https://youtube.com", nil),
		login("host-port", "https://mail.google.com:8443", &host),
		login("starts", "https://www.google.com/a", &starts),
		login("exact", "https://www.google.com/a/b", &exact),
		login("never", "https://www.google.com", &never),
		login("regex", `^https://www\.google\.com/a/.*$`, &regex),
		login("other", "https://example.com", nil),
	}
	domains := &vault.DomainsData{EquivalentDomains: [][]string{{"google.com", "youtube.com"}}}
	got := map[string]bool{}
	for _, c := range ciphersForURL(ciphers, "https://www.google.com/a/b", domains) {
		got[c.Name] = true
	}
	for _, name := range []string{"domain", "equivalent", "starts", "exact", "regex"} {
		if !got[name] {
			t.Errorf("expected %s to match", name)
		}
	}
	for _, name := range []string{"host-port", "never", "other"} {
		if got[name] {
			t.Errorf("did not expect %s to match", name)
		}
	}
}

func TestSearchCiphersBasic(t *testing.T) {
	notes := "Archived Café"
	user := "alice@mycompany.com"
	c := &vault.CipherView{ID: "0f1e2d3c-aaaa-bbbb-cccc-000000000000", Name: "Email Work MyCompany", Type: vault.CipherTypeLogin,
		Notes: &notes, Login: &vault.LoginView{Username: &user}}
	for _, q := range []string{"email work", "alice mycompany", "alice archived", "mycomp mail", "cafe", "0f1e2d3c"} {
		if len(searchCiphersBasic([]*vault.CipherView{c}, q)) != 1 {
			t.Errorf("query %q should match", q)
		}
	}
	for _, q := range []string{"bob", "0f1e2d"} {
		if len(searchCiphersBasic([]*vault.CipherView{c}, q)) != 0 {
			t.Errorf("query %q should not match", q)
		}
	}
}
