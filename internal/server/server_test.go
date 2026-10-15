package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/api"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/vault"
)

// The fixtures were captured from a Vaultwarden test account: token.json and
// sync.json are the raw encrypted server responses, and
// reference-responses.json holds what the official `bw serve` (CLI 2026.9.1)
// returned for the same vault state. The test asserts byte-level parity
// (values and key order) of the decrypted output.
const fixturePassword = "Correct-Horse-Battery-1"

func newFixtureServer(t *testing.T) (*Server, func()) {
	t.Helper()
	token, err := os.ReadFile("testdata/token.json")
	if err != nil {
		t.Fatal(err)
	}
	sync, err := os.ReadFile("testdata/sync.json")
	if err != nil {
		t.Fatal(err)
	}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/identity/connect/token":
			_, _ = w.Write(token)
		case "/api/sync":
			_, _ = w.Write(sync)
		case "/api/accounts/revision-date":
			_, _ = w.Write([]byte("0"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	urls := api.ResolveURLs(fake.URL, "", "")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	v := vault.New(api.NewClient(urls, "test-device"), log)
	ctx := context.Background()
	if err := v.LoginAPIKey(ctx, "user.test", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := v.Sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(fixturePassword); err != nil {
		t.Fatal(err)
	}
	return New(v, Options{Hostname: "all", Port: 8087, Logger: log}), fake.Close
}

var ignoredKeys = map[string]bool{"url": true, "accessUrl": true, "serverUrl": true, "lastSync": true}

// canonical renders JSON preserving key order, replacing ignored values.
func canonical(t *testing.T, raw []byte) string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var b strings.Builder
	var walk func(skip bool) error
	walk = func(skip bool) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch d := tok.(type) {
		case json.Delim:
			switch d {
			case '{':
				b.WriteString("{")
				first := true
				for dec.More() {
					kt, err := dec.Token()
					if err != nil {
						return err
					}
					k := kt.(string)
					if !first {
						b.WriteString(",")
					}
					first = false
					fmt.Fprintf(&b, "%q:", k)
					if err := walk(ignoredKeys[k]); err != nil {
						return err
					}
				}
				_, err := dec.Token()
				b.WriteString("}")
				return err
			case '[':
				b.WriteString("[")
				first := true
				for dec.More() {
					if !first {
						b.WriteString(",")
					}
					first = false
					if err := walk(skip); err != nil {
						return err
					}
				}
				_, err := dec.Token()
				b.WriteString("]")
				return err
			}
		default:
			if skip {
				b.WriteString(`"<ignored>"`)
				return nil
			}
			out, _ := json.Marshal(d)
			b.Write(out)
		}
		return nil
	}
	if err := walk(false); err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return b.String()
}

func TestParityWithOfficialCLI(t *testing.T) {
	srv, done := newFixtureServer(t)
	defer done()
	raw, err := os.ReadFile("testdata/reference-responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]struct {
		Path     string          `json:"path"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	for name, g := range golden {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, g.Path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			want := canonical(t, g.Response)
			got := canonical(t, rec.Body.Bytes())
			if want != got {
				t.Errorf("GET %s mismatch\nwant: %s\ngot:  %s", g.Path, want, got)
			}
		})
	}
}

func TestErrorsAndOriginProtection(t *testing.T) {
	srv, done := newFixtureServer(t)
	defer done()
	h := srv.Handler()
	cases := []struct {
		method, path, body, origin string
		status                     int
		contains                   string
	}{
		{"GET", "/object/item/00000000-0000-0000-0000-000000000000", "", "", 400, `"message":"Not found."`},
		{"GET", "/object/bogus/x", "", "", 400, `"message":"Unknown object."`},
		{"GET", "/object/item/e", "", "", 400, "More than one result was found"},
		{"GET", "/object/send/notaguid", "", "", 400, "is not a GUID"},
		{"POST", "/unlock", "{}", "", 400, "Master password is required"},
		{"POST", "/unlock", `{"password":"nope"}`, "", 400, "Cryptography error"},
		{"GET", "/status", "", "https://evil.example", 403, "Forbidden"},
		{"GET", "/status", "", "", 200, `"status":"unlocked"`},
	}
	for _, c := range cases {
		var body io.Reader
		if c.body != "" {
			body = strings.NewReader(c.body)
		}
		req := httptest.NewRequest(c.method, c.path, body)
		if c.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.contains) {
			t.Errorf("%s %s: got %d %s, want %d containing %q", c.method, c.path, rec.Code, rec.Body.String(), c.status, c.contains)
		}
	}
}

func TestLockBlocksVaultAccess(t *testing.T) {
	srv, done := newFixtureServer(t)
	defer done()
	h := srv.Handler()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	do("POST", "/lock", "")
	if rec := do("GET", "/list/object/items", ""); !strings.Contains(rec.Body.String(), "Vault is locked.") {
		t.Fatalf("expected locked error, got %s", rec.Body.String())
	}
	if rec := do("POST", "/unlock", `{"password":"`+fixturePassword+`"}`); rec.Code != 200 {
		t.Fatalf("unlock failed: %s", rec.Body.String())
	}
	if rec := do("GET", "/list/object/items", ""); rec.Code != 200 {
		t.Fatalf("list after unlock failed: %s", rec.Body.String())
	}
}
