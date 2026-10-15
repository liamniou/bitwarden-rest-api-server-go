package vault

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

// JSON helpers for loosely typed request bodies (the CLI accepts arbitrary JSON).

func has(m map[string]any, k string) bool {
	_, ok := m[k]
	return ok
}

func optString(m map[string]any, k string) *string {
	switch t := m[k].(type) {
	case string:
		return &t
	case json.Number:
		s := t.String()
		return &s
	case float64:
		s := strconv.FormatFloat(t, 'f', -1, 64)
		return &s
	case bool:
		s := strconv.FormatBool(t)
		return &s
	}
	return nil
}

func optInt(m map[string]any, k string) *int {
	switch t := m[k].(type) {
	case float64:
		if t == math.Trunc(t) {
			i := int(t)
			return &i
		}
	case json.Number:
		if i, err := t.Int64(); err == nil {
			ii := int(i)
			return &ii
		}
	case string:
		if i, err := strconv.Atoi(t); err == nil {
			return &i
		}
	}
	return nil
}

func optBool(m map[string]any, k string) bool {
	switch t := m[k].(type) {
	case bool:
		return t
	case string:
		return t == "true"
	case float64:
		return t != 0
	}
	return false
}

func optMap(m map[string]any, k string) map[string]any {
	if mm, ok := m[k].(map[string]any); ok {
		return mm
	}
	return nil
}

func optSlice(m map[string]any, k string) ([]any, bool) {
	s, ok := m[k].([]any)
	return s, ok
}

func optTime(m map[string]any, k string) *time.Time {
	s := optString(m, k)
	if s == nil || *s == "" {
		return nil
	}
	return ParseTime(s)
}

func optStringSlice(m map[string]any, k string) ([]string, bool) {
	raw, ok := optSlice(m, k)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out, true
}

// ApplyCipherExport implements CipherExport.toView(req, view).
func ApplyCipherExport(req map[string]any, view *CipherView) (*CipherView, error) {
	if req == nil {
		return nil, errors.New("invalid request")
	}
	if view == nil {
		view = &CipherView{ViewPassword: true, Edit: true, CollectionIDs: []string{}}
	}
	t := optInt(req, "type")
	if t == nil {
		t = new(int)
	}
	view.Type = *t
	view.FolderID = optString(req, "folderId")
	if view.OrganizationID == nil {
		view.OrganizationID = optString(req, "organizationId")
	}
	if ids, ok := optStringSlice(req, "collectionIds"); ok || view.CollectionIDs != nil {
		seen := map[string]bool{}
		merged := []string{}
		for _, id := range append(append([]string{}, view.CollectionIDs...), ids...) {
			if !seen[id] {
				seen[id] = true
				merged = append(merged, id)
			}
		}
		view.CollectionIDs = merged
	}
	view.Name = deref(optString(req, "name"))
	view.Notes = optString(req, "notes")
	view.Favorite = optBool(req, "favorite")
	view.Reprompt = 0
	if r := optInt(req, "reprompt"); r != nil {
		view.Reprompt = *r
	}
	if k := optString(req, "key"); k != nil {
		view.Key = k
	}
	if fs, ok := optSlice(req, "fields"); ok {
		view.Fields = make([]FieldView, 0, len(fs))
		for _, f := range fs {
			fm, _ := f.(map[string]any)
			if fm == nil {
				continue
			}
			ft := 0
			if v := optInt(fm, "type"); v != nil {
				ft = *v
			}
			view.Fields = append(view.Fields, FieldView{Name: optString(fm, "name"), Value: optString(fm, "value"), Type: ft, LinkedID: optInt(fm, "linkedId")})
		}
	}
	switch view.Type {
	case CipherTypeLogin:
		if lm := optMap(req, "login"); lm != nil {
			l := &LoginView{Username: optString(lm, "username"), Password: optString(lm, "password"), Totp: optString(lm, "totp")}
			if us, ok := optSlice(lm, "uris"); ok {
				l.URIs = make([]LoginURIView, 0, len(us))
				for _, u := range us {
					um, _ := u.(map[string]any)
					if um == nil {
						continue
					}
					l.URIs = append(l.URIs, LoginURIView{URI: optString(um, "uri"), Match: optInt(um, "match")})
				}
			}
			if fcs, ok := optSlice(lm, "fido2Credentials"); ok {
				l.Fido2Credentials = make([]Fido2CredentialView, 0, len(fcs))
				for _, f := range fcs {
					fm, _ := f.(map[string]any)
					if fm == nil {
						continue
					}
					l.Fido2Credentials = append(l.Fido2Credentials, Fido2CredentialView{
						CredentialID: deref(optString(fm, "credentialId")), KeyType: deref(optString(fm, "keyType")),
						KeyAlgorithm: deref(optString(fm, "keyAlgorithm")), KeyCurve: deref(optString(fm, "keyCurve")),
						KeyValue: deref(optString(fm, "keyValue")), RpID: deref(optString(fm, "rpId")),
						UserHandle: optString(fm, "userHandle"), UserName: optString(fm, "userName"),
						Counter: deref(optString(fm, "counter")), RpName: optString(fm, "rpName"),
						UserDisplayName: optString(fm, "userDisplayName"), Discoverable: deref(optString(fm, "discoverable")),
						CreationDate: optTime(fm, "creationDate"),
					})
				}
			}
			view.Login = l
		}
	case CipherTypeSecureNote:
		if sm := optMap(req, "secureNote"); sm != nil {
			st := 0
			if v := optInt(sm, "type"); v != nil {
				st = *v
			}
			view.SecureNoteType = &st
		}
	default:
		name, fields := typedFields(view.Type)
		if fields == nil {
			break
		}
		sub := optMap(req, name)
		if sub == nil {
			break
		}
		if view.Type == CipherTypeSSHKey {
			for _, f := range fields {
				s := optString(sub, f)
				if s == nil || strings.TrimSpace(*s) == "" {
					switch f {
					case "privateKey":
						return nil, errors.New("SSH key private key is required.")
					case "publicKey":
						return nil, errors.New("SSH key public key is required.")
					default:
						return nil, errors.New("SSH key fingerprint is required.")
					}
				}
			}
		}
		view.Typed = map[string]*string{}
		for _, f := range fields {
			view.Typed[f] = optString(sub, f)
		}
	}
	if phs, ok := optSlice(req, "passwordHistory"); ok {
		view.PasswordHistory = make([]PasswordHistoryView, 0, len(phs))
		for _, p := range phs {
			pm, _ := p.(map[string]any)
			if pm == nil {
				continue
			}
			view.PasswordHistory = append(view.PasswordHistory, PasswordHistoryView{Password: deref(optString(pm, "password")), LastUsedDate: optTime(pm, "lastUsedDate")})
		}
	}
	if d := optTime(req, "creationDate"); d != nil {
		view.CreationDate = d
	}
	if d := optTime(req, "revisionDate"); d != nil {
		view.RevisionDate = d
	}
	if d := optTime(req, "deletedDate"); d != nil {
		view.DeletedDate = d
	}
	if d := optTime(req, "archivedDate"); d != nil {
		view.ArchivedDate = d
	}
	return view, nil
}

// CloneCipherView makes a deep enough copy for safe mutation.
func CloneCipherView(c *CipherView) *CipherView {
	cp := *c
	cp.search = nil
	if c.Login != nil {
		l := *c.Login
		l.URIs = append([]LoginURIView(nil), c.Login.URIs...)
		l.Fido2Credentials = append([]Fido2CredentialView(nil), c.Login.Fido2Credentials...)
		if c.Login.URIs == nil {
			l.URIs = nil
		}
		if c.Login.Fido2Credentials == nil {
			l.Fido2Credentials = nil
		}
		cp.Login = &l
	}
	if c.Typed != nil {
		cp.Typed = map[string]*string{}
		for k, v := range c.Typed {
			cp.Typed[k] = v
		}
	}
	if c.Fields != nil {
		cp.Fields = append([]FieldView{}, c.Fields...)
	}
	if c.PasswordHistory != nil {
		cp.PasswordHistory = append([]PasswordHistoryView{}, c.PasswordHistory...)
	}
	if c.Attachments != nil {
		cp.Attachments = append([]AttachmentView{}, c.Attachments...)
	}
	cp.CollectionIDs = append([]string{}, c.CollectionIDs...)
	return &cp
}

// adjustPasswordHistory implements updateModelfromExistingCipher + length trimming.
func adjustPasswordHistory(model, existing *CipherView) {
	if existing == nil {
		return
	}
	now := time.Now().UTC()
	model.PasswordHistory = append([]PasswordHistoryView{}, existing.PasswordHistory...)
	if model.Type == CipherTypeLogin && existing.Type == CipherTypeLogin {
		if model.Login == nil {
			model.Login = &LoginView{}
		}
		var oldPw string
		if existing.Login != nil {
			oldPw = deref(existing.Login.Password)
		}
		if oldPw != "" && oldPw != deref(model.Login.Password) {
			model.PasswordHistory = append([]PasswordHistoryView{{Password: oldPw, LastUsedDate: &now}}, model.PasswordHistory...)
			model.Login.PasswordRevisionDate = &now
		} else if existing.Login != nil {
			model.Login.PasswordRevisionDate = existing.Login.PasswordRevisionDate
		}
	}
	for _, ef := range existing.Fields {
		if ef.Type != FieldTypeHidden || deref(ef.Name) == "" || deref(ef.Value) == "" {
			continue
		}
		var matched *FieldView
		for i := range model.Fields {
			f := &model.Fields[i]
			if f.Type == FieldTypeHidden && deref(f.Name) != "" && deref(f.Name) == deref(ef.Name) {
				matched = f
				break
			}
		}
		if matched == nil || deref(matched.Value) != deref(ef.Value) {
			model.PasswordHistory = append([]PasswordHistoryView{{Password: deref(ef.Name) + ": " + deref(ef.Value), LastUsedDate: &now}}, model.PasswordHistory...)
		}
	}
	if len(model.PasswordHistory) == 0 {
		model.PasswordHistory = nil
	} else if len(model.PasswordHistory) > 5 {
		model.PasswordHistory = model.PasswordHistory[:5]
	}
}
