package vault

import (
	"errors"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/crypto"
)

// encryptCipherLocked builds a CipherRequest body. Fields are encrypted with
// the per-cipher key when present, otherwise with the user/org key.
// Callers must hold v.mu (read or write).
func (v *Vault) encryptCipherLocked(view *CipherView, orig *CipherData) (map[string]any, error) {
	vaultKey := v.vaultKeyLocked(view.OrganizationID)
	if vaultKey == nil {
		if view.OrganizationID != nil {
			return nil, errors.New("No encryption key for this organization.")
		}
		return nil, ErrLocked
	}
	key := vaultKey
	if view.Key != nil && *view.Key != "" {
		ck, err := crypto.DecryptToKey(vaultKey, *view.Key)
		if err != nil {
			return nil, errors.New("Unable to decrypt the cipher key.")
		}
		key = ck
	}
	var encErr error
	enc := func(s *string) any {
		if s == nil || *s == "" {
			return nil
		}
		out, err := crypto.EncryptString(key, *s)
		if err != nil {
			encErr = err
			return nil
		}
		return out
	}

	req := map[string]any{
		"type":           view.Type,
		"folderId":       nullable(view.FolderID),
		"organizationId": nullable(view.OrganizationID),
		"name":           enc(&view.Name),
		"notes":          enc(view.Notes),
		"favorite":       view.Favorite,
		"reprompt":       view.Reprompt,
		"encryptedFor":   v.userID,
		"archivedDate":   JSTime(view.ArchivedDate),
	}
	if view.Key != nil {
		req["key"] = *view.Key
	} else {
		req["key"] = nil
	}
	if orig != nil {
		req["lastKnownRevisionDate"] = orig.RevisionDate
	} else {
		req["lastKnownRevisionDate"] = nil
	}

	switch view.Type {
	case CipherTypeLogin:
		l := view.Login
		if l == nil {
			l = &LoginView{}
		}
		lm := map[string]any{
			"username":             enc(l.Username),
			"password":             enc(l.Password),
			"totp":                 enc(l.Totp),
			"passwordRevisionDate": JSTime(l.PasswordRevisionDate),
			"autofillOnPageLoad":   l.AutofillOnPageLoad,
		}
		uris := make([]map[string]any, 0, len(l.URIs))
		for _, u := range l.URIs {
			um := map[string]any{"uri": enc(u.URI), "match": u.Match, "uriChecksum": nil}
			if u.URI != nil && *u.URI != "" {
				cs, err := uriChecksum(key, *u.URI)
				if err != nil {
					return nil, err
				}
				um["uriChecksum"] = cs
			}
			uris = append(uris, um)
		}
		lm["uris"] = uris
		if l.Fido2Credentials != nil {
			fcs := make([]map[string]any, 0, len(l.Fido2Credentials))
			for _, f := range l.Fido2Credentials {
				fcs = append(fcs, map[string]any{
					"credentialId": enc(&f.CredentialID), "keyType": enc(&f.KeyType), "keyAlgorithm": enc(&f.KeyAlgorithm),
					"keyCurve": enc(&f.KeyCurve), "keyValue": enc(&f.KeyValue), "rpId": enc(&f.RpID),
					"rpName": enc(f.RpName), "counter": enc(&f.Counter), "userHandle": enc(f.UserHandle),
					"userName": enc(f.UserName), "userDisplayName": enc(f.UserDisplayName),
					"discoverable": enc(&f.Discoverable), "creationDate": JSTime(f.CreationDate),
				})
			}
			lm["fido2Credentials"] = fcs
		}
		req["login"] = lm
	case CipherTypeSecureNote:
		t := 0
		if view.SecureNoteType != nil {
			t = *view.SecureNoteType
		}
		req["secureNote"] = map[string]any{"type": t}
	default:
		if name, fields := typedFields(view.Type); fields != nil {
			sub := map[string]any{}
			for _, f := range fields {
				sub[f] = enc(view.Typed[f])
			}
			req[name] = sub
		}
	}
	if view.Fields != nil {
		fs := make([]map[string]any, 0, len(view.Fields))
		for _, f := range view.Fields {
			fs = append(fs, map[string]any{"type": f.Type, "name": enc(f.Name), "value": enc(f.Value), "linkedId": f.LinkedID})
		}
		req["fields"] = fs
	}
	if view.PasswordHistory != nil {
		ph := make([]map[string]any, 0, len(view.PasswordHistory))
		for _, h := range view.PasswordHistory {
			pw := h.Password
			ph = append(ph, map[string]any{"lastUsedDate": JSTime(h.LastUsedDate), "password": enc(&pw)})
		}
		req["passwordHistory"] = ph
	}
	if view.Attachments != nil {
		atts := map[string]any{}
		atts2 := map[string]any{}
		for _, a := range view.Attachments {
			var fileName, attKey any
			if a.Key != nil {
				fileName = enc(a.FileName)
				wrapped, err := crypto.Encrypt(key, a.Key.Bytes())
				if err != nil {
					return nil, err
				}
				attKey = wrapped.String()
			} else if orig != nil {
				for _, oa := range orig.Attachments {
					if oa.ID == a.ID {
						fileName = nullable(oa.FileName)
						attKey = nullable(oa.Key)
					}
				}
			}
			atts[a.ID] = fileName
			a2 := map[string]any{"fileName": fileName, "key": attKey}
			if orig != nil {
				a2["lastKnownRevisionDate"] = orig.RevisionDate
			}
			atts2[a.ID] = a2
		}
		req["attachments"] = atts
		req["attachments2"] = atts2
	}
	if encErr != nil {
		return nil, encErr
	}
	return req, nil
}
