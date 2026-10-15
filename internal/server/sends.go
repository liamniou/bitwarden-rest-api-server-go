package server

import (
	"encoding/base64"
	"strings"
	"time"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/crypto"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/vault"
)

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

const (
	authTypeEmail    = 0
	authTypePassword = 1
	authTypeNone     = 2
)

var sendTypeNames = map[int]string{0: "Text", 1: "File", 2: "Item"}

func (s *Server) sendURL() string { return s.v.Client.URLs.SendURL() }

// searchSends mirrors SearchService.searchSends.
func searchSends(sends []*vault.SendView, query string) []*vault.SendView {
	query = vault.NormalizeSearch(strings.TrimSpace(query))
	var hi, lo []*vault.SendView
	for _, sd := range sends {
		name := strings.ToLower(derefStr(sd.Name))
		switch {
		case sd.Name != nil && strings.Contains(name, query):
			hi = append(hi, sd)
		case len(query) >= 8 && (strings.HasPrefix(sd.ID, query) || strings.HasPrefix(strings.ToLower(sd.AccessID), query) ||
			(sd.FileID != nil && strings.HasPrefix(*sd.FileID, query))):
			lo = append(lo, sd)
		case sd.Notes != nil && strings.Contains(strings.ToLower(*sd.Notes), query):
			lo = append(lo, sd)
		case sd.Text != nil && strings.Contains(strings.ToLower(*sd.Text), query):
			lo = append(lo, sd)
		case sd.FileName != nil && strings.Contains(strings.ToLower(*sd.FileName), query):
			lo = append(lo, sd)
		}
	}
	return append(hi, lo...)
}

func (s *Server) sendList(q *request) *Response {
	sends := s.v.Sends()
	if search := q.optStr("search"); strings.TrimSpace(search) != "" {
		sends = searchSends(sends, search)
	}
	items := make([]any, 0, len(sends))
	for _, sd := range sends {
		items = append(items, sd.ToCLI(s.sendURL()))
	}
	return success(listResponse(items))
}

func (s *Server) sendGet(id string) *Response {
	if !isGUID(id) {
		return badRequest("`" + id + "` is not a GUID.")
	}
	sd := s.v.Send(strings.ToLower(id))
	if sd == nil {
		return notFound()
	}
	return success(sd.ToCLI(s.sendURL()))
}

func (s *Server) sendDelete(q *request, id string) *Response {
	if s.v.Send(id) == nil {
		return notFound()
	}
	if err := s.v.DeleteSend(q.r.Context(), id); err != nil {
		return errFrom(err)
	}
	return success(nil)
}

func (s *Server) sendRemovePassword(q *request) *Response {
	sd, err := s.v.RemoveSendPassword(q.r.Context(), q.r.PathValue("id"))
	if err != nil {
		return errFrom(err)
	}
	return success(sd.ToCLI(s.sendURL()))
}

// sendInput is the parsed SendResponse-shaped request body.
type sendInput struct {
	raw            map[string]any
	typ            *int
	name, notes    *string
	key            *string
	text           *string
	textHidden     *bool
	fileName       *string
	maxAccessCount *int
	deletionDate   *time.Time
	expirationDate *time.Time
	password       *string
	emails         []string
	hasEmails      bool
	disabled       bool
	hideEmail      bool
}

func parseSendInput(m map[string]any) (*sendInput, *Response) {
	in := &sendInput{raw: m}
	in.typ = optIntAny(m["type"])
	in.name, _ = strPtrAny(m["name"])
	in.notes, _ = strPtrAny(m["notes"])
	in.key, _ = strPtrAny(m["key"])
	if t, ok := m["text"].(map[string]any); ok {
		in.text, _ = strPtrAny(t["text"])
		if h, ok := t["hidden"].(bool); ok {
			in.textHidden = &h
		}
	}
	if f, ok := m["file"].(map[string]any); ok {
		in.fileName, _ = strPtrAny(f["fileName"])
	}
	in.maxAccessCount = optIntAny(m["maxAccessCount"])
	if raw, ok := m["deletionDate"]; ok && raw != nil {
		s, _ := raw.(string)
		in.deletionDate = vault.ParseTime(&s)
		if in.deletionDate == nil {
			in.deletionDate = &time.Time{}
		}
	}
	if raw, ok := m["expirationDate"]; ok && raw != nil {
		s, _ := raw.(string)
		in.expirationDate = vault.ParseTime(&s)
		if in.expirationDate == nil {
			return nil, badRequest("Unable to parse expirationDate: Invalid Date")
		}
	}
	if p, ok := m["password"].(string); ok {
		in.password = &p
	}
	if es, ok := m["emails"].([]any); ok {
		in.hasEmails = true
		for _, e := range es {
			if s, ok := e.(string); ok {
				in.emails = append(in.emails, s)
			}
		}
	}
	in.disabled, _ = m["disabled"].(bool)
	in.hideEmail, _ = m["hideEmail"].(bool)
	return in, nil
}

func strPtrAny(v any) (*string, bool) {
	if s, ok := v.(string); ok {
		return &s, true
	}
	return nil, false
}

func optIntAny(v any) *int {
	if f, ok := v.(float64); ok {
		i := int(f)
		return &i
	}
	return nil
}

func (s *Server) sendCreate(q *request) *Response {
	m := q.bodyMap()
	if m == nil {
		return badRequest("Error parsing the encoded request data.")
	}
	in, r := parseSendInput(m)
	if r != nil {
		return r
	}
	if in.deletionDate == nil || in.deletionDate.IsZero() || !in.deletionDate.After(time.Now()) {
		return badRequest("Must specify a valid deletion date after the current time")
	}
	text := in.text
	if text == nil {
		text = q.opt("text")
	}
	hidden := false
	if in.textHidden != nil {
		hidden = *in.textHidden
	} else {
		hidden = q.optBool("hidden")
	}
	password := in.password
	if password == nil {
		password = q.opt("password")
	}
	emails := in.emails
	if !in.hasEmails {
		if e := q.opt("emails"); e != nil {
			emails = []string{*e}
		}
	}
	maxAccess := in.maxAccessCount
	if maxAccess == nil {
		if v := q.opt("maxAccessCount"); v != nil {
			n := q.optInt(0, "maxAccessCount")
			maxAccess = &n
		}
	}
	hasEmails := len(emails) > 0
	hasPassword := password != nil && strings.TrimSpace(*password) != ""
	if hasEmails && hasPassword {
		return badRequest("--password and --emails are mutually exclusive.")
	}
	authType := authTypeNone
	if hasEmails {
		authType = authTypeEmail
	} else if hasPassword {
		authType = authTypePassword
	}
	typ := -1
	if in.typ != nil {
		typ = *in.typ
	}
	switch typ {
	case vault.SendTypeFile:
		return errResp("Creating a file-based Send is unsupported through the `serve` command at this time.")
	case vault.SendTypeText:
		if text == nil {
			return badRequest("Must specify text content to Send either with the --text option or in the request JSON.")
		}
	case 2:
		return badRequest("Item type Send functionality not yet available")
	default:
		name, ok := sendTypeNames[typ]
		if !ok {
			name = "undefined"
		}
		return badRequest("Unknown Send type " + name + ". Valid types are: file, text")
	}
	material := crypto.RandomBytes(16)
	body, err := s.encryptSend(in, material, typ, text, hidden, fileNameOrNil(in), password, emails, maxAccess, authType)
	if err != nil {
		return errFrom(err)
	}
	sd, err := s.v.SaveSend(q.r.Context(), "", body)
	if err != nil {
		return errFrom(err)
	}
	return success(sd.ToCLI(s.sendURL()))
}

func fileNameOrNil(in *sendInput) *string { return in.fileName }

func (s *Server) encryptSend(in *sendInput, material []byte, typ int, text *string, hidden bool, fileName *string,
	password *string, emails []string, maxAccess *int, authType int) (map[string]any, error) {
	userKey := s.v.UserKey()
	if userKey == nil {
		return nil, vault.ErrLocked
	}
	sendKey, err := crypto.DeriveSendKey(material)
	if err != nil {
		return nil, err
	}
	encKey, err := crypto.Encrypt(userKey, material)
	if err != nil {
		return nil, err
	}
	enc := func(p *string) any {
		if p == nil {
			return nil
		}
		out, e := crypto.EncryptString(sendKey, *p)
		if e != nil {
			err = e
			return nil
		}
		return out
	}
	body := map[string]any{
		"type":           typ,
		"name":           enc(in.name),
		"notes":          enc(in.notes),
		"key":            encKey.String(),
		"maxAccessCount": maxAccess,
		"deletionDate":   vault.JSTime(in.deletionDate),
		"expirationDate": vault.JSTime(in.expirationDate),
		"disabled":       in.disabled,
		"hideEmail":      in.hideEmail,
		"authType":       authType,
		"emails":         nil,
	}
	if len(emails) > 0 {
		clean := make([]string, 0, len(emails))
		for _, e := range emails {
			clean = append(clean, strings.TrimSpace(e))
		}
		body["emails"] = strings.ToLower(strings.Join(clean, ","))
		body["password"] = nil
	} else if password != nil {
		h, e := crypto.SendPasswordHash(*password, material)
		if e != nil {
			return nil, e
		}
		body["password"] = h
	}
	switch typ {
	case vault.SendTypeText:
		body["text"] = map[string]any{"text": enc(text), "hidden": hidden}
	case vault.SendTypeFile:
		body["file"] = map[string]any{"fileName": enc(fileName)}
	}
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (s *Server) sendEdit(q *request, pathID string) *Response {
	m := q.bodyMap()
	if m == nil {
		return badRequest("Error parsing the encoded request data.")
	}
	in, r := parseSendInput(m)
	if r != nil {
		return r
	}
	id := q.optStr("itemId", "itemid")
	if id == "" {
		id = pathID
	}
	if e := q.opt("emails"); e != nil && *e != "" {
		in.emails, in.hasEmails = []string{*e}, true
	}
	if p := q.opt("password"); p != nil && *p != "" {
		in.password = p
	}
	if in.password != nil && *in.password == "" {
		in.password = nil
	}
	hasEmails := len(in.emails) > 0
	hasPassword := in.password != nil && strings.TrimSpace(*in.password) != ""
	if hasEmails && hasPassword {
		return badRequest("--password and --emails are mutually exclusive.")
	}
	authType := authTypeNone
	if hasEmails {
		authType = authTypeEmail
	} else if hasPassword {
		authType = authTypePassword
	}
	if id == "" {
		return errResp("`itemid` was not provided.")
	}
	id = strings.ToLower(id)
	existing := s.v.Send(id)
	if existing == nil {
		return notFound()
	}
	if in.typ == nil || *in.typ != existing.Type {
		return badRequest("Cannot change a Send's type")
	}
	if existing.Type == vault.SendTypeFile && !s.v.HasPremium() {
		return errResp("Premium status is required to use this feature.")
	}
	material := existing.KeyMaterial
	if in.key != nil {
		if k, err := base64.StdEncoding.DecodeString(*in.key); err == nil && len(k) > 0 {
			material = k
		}
	}
	if len(material) == 0 {
		return errResp("Unable to decrypt the Send key.")
	}
	fileName := in.fileName
	if fileName == nil {
		fileName = existing.FileName
	}
	hidden := false
	if in.textHidden != nil {
		hidden = *in.textHidden
	}
	body, err := s.encryptSend(in, material, existing.Type, in.text, hidden, fileName, in.password, in.emails, in.maxAccessCount, authType)
	if err != nil {
		return errFrom(err)
	}
	if _, err := s.v.SaveSend(q.r.Context(), id, body); err != nil {
		return errFrom(err)
	}
	return s.sendGet(id)
}
