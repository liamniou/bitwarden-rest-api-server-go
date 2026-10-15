// Package server exposes the Bitwarden CLI `bw serve` Vault Management API.
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/vault"
)

// Response mirrors the CLI Response envelope.
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`

	file     []byte
	fileName string
}

func success(data any) *Response { return &Response{Success: true, Data: data} }

func errResp(msg string) *Response { return &Response{Success: false, Message: msg} }

func errFrom(err error) *Response {
	if err == nil {
		return errResp("An unknown error occurred.")
	}
	return errResp(err.Error())
}

func notFound() *Response { return errResp("Not found.") }

func badRequest(msg string) *Response { return errResp(msg) }

func multipleResults(ids []string) *Response {
	msg := "More than one result was found. Try getting a specific object by `id` instead. The following objects were found:"
	for _, id := range ids {
		msg += "\n" + id
	}
	r := errResp(msg)
	r.Data = ids
	return r
}

func fileResponse(data []byte, name string) *Response {
	return &Response{Success: true, file: data, fileName: name}
}

func stringResponse(s string) *vault.OMap {
	return vault.NewOMap().Set("object", "string").Set("data", s)
}

func stringResponseNull(s *string) *vault.OMap {
	m := vault.NewOMap().Set("object", "string")
	if s == nil {
		return m.Set("data", nil)
	}
	return m.Set("data", *s)
}

func messageResponse(title string, message *string) *vault.OMap {
	m := vault.NewOMap().Set("noColor", false).Set("object", "message").Set("title", title)
	if message == nil {
		m.Set("message", nil)
	} else {
		m.Set("message", *message)
	}
	return m
}

func listResponse(items []any) *vault.OMap {
	if items == nil {
		items = []any{}
	}
	return vault.NewOMap().Set("object", "list").Set("data", items)
}

func templateResponse(t any) *vault.OMap {
	return vault.NewOMap().Set("object", "template").Set("template", t)
}

// Options controls listening and request filtering.
type Options struct {
	Hostname                string
	Port                    int
	DisableOriginProtection bool
	Logger                  *slog.Logger
}

// Server wires HTTP routes to the vault.
type Server struct {
	v    *vault.Vault
	opts Options
	log  *slog.Logger
	mux  *http.ServeMux
}

func New(v *vault.Vault, opts Options) *Server {
	s := &Server{v: v, opts: opts, log: opts.Logger, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	h := func(pattern string, fn func(*request) *Response, locked bool) {
		s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			req, err := newRequest(r)
			if err != nil {
				s.write(w, r, badRequest(err.Error()))
				return
			}
			if locked {
				if err := s.v.CheckUnlocked(); err != nil {
					s.write(w, r, errFrom(err))
					return
				}
			}
			s.write(w, r, fn(req))
		})
	}
	h("GET /generate", s.generate, false)
	h("GET /status", s.status, false)
	h("GET /list/object/{object}", s.list, true)
	h("GET /send/list", s.sendList, true)
	h("POST /sync", s.sync, false)
	h("POST /lock", s.lock, false)
	h("POST /unlock", s.unlock, false)
	h("POST /confirm/{object}/{id}", s.confirm, true)
	h("POST /restore/{object}/{id}", s.restore, true)
	h("POST /move/{id}/{organizationId}", s.move, true)
	h("POST /attachment", s.createAttachment, true)
	h("POST /send/{id}/remove-password", s.sendRemovePassword, true)
	h("POST /object/{object}", s.create, true)
	h("PUT /object/{object}/{id}", s.edit, true)
	h("GET /object/{object}/{id}", s.get, true)
	h("DELETE /object/{object}/{id}", s.delete, true)
	h("POST /archive/{object}/{id}", s.archive, true)
	h("GET /device-approval/{organizationId}", s.deviceApprovalList, true)
	h("POST /device-approval/{organizationId}/approve-all", s.deviceApprovalApproveAll, true)
	h("POST /device-approval/{organizationId}/approve/{requestId}", s.deviceApprovalApprove, true)
	h("POST /device-approval/{organizationId}/deny-all", s.deviceApprovalDenyAll, true)
	h("POST /device-approval/{organizationId}/deny/{requestId}", s.deviceApprovalDeny, true)
}

// Handler returns the root handler including origin protection and logging.
func (s *Server) Handler() http.Handler {
	var allowed map[string]bool
	if s.opts.Hostname != "all" {
		allowed = allowedHosts(s.opts.Hostname, s.opts.Port)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if !s.opts.DisableOriginProtection {
			if allowed != nil && !allowed[strings.ToLower(r.Host)] {
				s.log.Warn(fmt.Sprintf("Blocking request with disallowed Host %q", r.Host))
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			if origin, ok := r.Header["Origin"]; ok {
				o := "(Origin header value missing)"
				if len(origin) > 0 && origin[0] != "" {
					o = origin[0]
				}
				s.log.Warn(fmt.Sprintf("Blocking request from %q", o))
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		s.mux.ServeHTTP(w, r)
		s.log.Debug("request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func allowedHosts(hostname string, port int) map[string]bool {
	p := strconv.Itoa(port)
	entries := []string{"localhost:" + p, "127.0.0.1:" + p, "[::1]:" + p, hostname + ":" + p}
	if port == 80 || port == 443 {
		entries = append(entries, "localhost", "127.0.0.1", "[::1]", hostname)
	}
	m := map[string]bool{}
	for _, e := range entries {
		m[strings.ToLower(e)] = true
	}
	return m
}

func (s *Server) write(w http.ResponseWriter, r *http.Request, resp *Response) {
	if resp == nil {
		resp = errResp("An unknown error occurred.")
	}
	if resp.file != nil {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": resp.fileName}))
		w.Header().Set("Content-Length", strconv.Itoa(len(resp.file)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp.file)
		return
	}
	env := vault.NewOMap().Set("success", resp.Success)
	if resp.Message != "" {
		env.Set("message", resp.Message)
	}
	if resp.Data != nil {
		env.Set("data", resp.Data)
	}
	body, err := vault.AppendJSON(make([]byte, 0, 4096), env)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, pretty := r.URL.Query()["pretty"]; pretty {
		var out bytes.Buffer
		if json.Indent(&out, body, "", "  ") == nil {
			body = out.Bytes()
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if !resp.Success {
		w.WriteHeader(http.StatusBadRequest)
	}
	_, _ = w.Write(body)
}

// request wraps the parsed query and body.
type request struct {
	r     *http.Request
	query url.Values
	body  any
}

const maxBody = 600 << 20

func newRequest(r *http.Request) (*request, error) {
	req := &request{r: r, query: r.URL.Query(), body: map[string]any{}}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch {
	case ct == "application/json" || strings.HasSuffix(ct, "+json"):
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			return nil, err
		}
		if len(strings.TrimSpace(string(raw))) > 0 {
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			var v any
			if err := dec.Decode(&v); err != nil {
				return nil, errors.New("invalid JSON body: " + err.Error())
			}
			req.body = v
		}
	case ct == "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err == nil {
			m := map[string]any{}
			for k, vs := range r.PostForm {
				if len(vs) > 0 {
					m[k] = vs[0]
				}
			}
			req.body = m
		}
	}
	return req, nil
}

// opt reads a query option the way the CLI normalizes `foo` / `fooBar` variants.
func (q *request) opt(names ...string) *string {
	for _, n := range names {
		if vs, ok := q.query[n]; ok && len(vs) > 0 {
			v := vs[0]
			return &v
		}
	}
	return nil
}

func (q *request) optStr(names ...string) string {
	if v := q.opt(names...); v != nil {
		return *v
	}
	return ""
}

// optBool mirrors CliUtils.convertBooleanOption.
func (q *request) optBool(names ...string) bool {
	v := q.opt(names...)
	if v == nil {
		return false
	}
	return *v == "" || strings.EqualFold(*v, "true")
}

// optInt mirrors CliUtils.convertNumberOption (parseInt semantics).
func (q *request) optInt(def int, names ...string) int {
	v := q.opt(names...)
	if v == nil {
		return def
	}
	m := regexp.MustCompile(`^\s*[-+]?\d+`).FindString(*v)
	if m == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(m))
	if err != nil {
		return def
	}
	return n
}

func (q *request) bodyMap() map[string]any {
	if m, ok := q.body.(map[string]any); ok {
		return m
	}
	return nil
}

var guidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

func isGUID(s string) bool { return guidRe.MatchString(s) }

func isNullOrWhitespace(s *string) bool { return s == nil || strings.TrimSpace(*s) == "" }
