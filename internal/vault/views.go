package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/crypto"
)

const decryptError = "[error: cannot decrypt]"

// CipherView is a decrypted cipher.
type CipherView struct {
	ID                  string
	OrganizationID      *string
	FolderID            *string
	Type                int
	Name                string
	Notes               *string
	Favorite            bool
	Reprompt            int
	Key                 *string // encrypted per-cipher key, if any
	Login               *LoginView
	SecureNoteType      *int
	Typed               map[string]*string // card / identity / sshKey / bankAccount / driversLicense / passport
	Fields              []FieldView
	PasswordHistory     []PasswordHistoryView
	Attachments         []AttachmentView
	CollectionIDs       []string
	RevisionDate        *time.Time
	CreationDate        *time.Time
	DeletedDate         *time.Time
	ArchivedDate        *time.Time
	Edit                bool
	ViewPassword        bool
	Permissions         *CipherPermissions
	OrganizationUseTotp bool

	search *SearchIndex
}

type LoginView struct {
	URIs                 []LoginURIView
	Username             *string
	Password             *string
	Totp                 *string
	PasswordRevisionDate *time.Time
	AutofillOnPageLoad   *bool
	Fido2Credentials     []Fido2CredentialView
}

type LoginURIView struct {
	URI   *string
	Match *int
}

type Fido2CredentialView struct {
	CredentialID    string
	KeyType         string
	KeyAlgorithm    string
	KeyCurve        string
	KeyValue        string
	RpID            string
	UserHandle      *string
	UserName        *string
	Counter         string
	RpName          *string
	UserDisplayName *string
	Discoverable    string
	CreationDate    *time.Time
}

type FieldView struct {
	Name     *string
	Value    *string
	Type     int
	LinkedID *int
}

type PasswordHistoryView struct {
	Password     string
	LastUsedDate *time.Time
}

type AttachmentView struct {
	ID       string
	URL      *string
	FileName *string
	Key      *crypto.SymmetricKey
	EncKey   *string
	Size     *string
	SizeName *string
}

func (c *CipherView) IsDeleted() bool  { return c.DeletedDate != nil }
func (c *CipherView) IsArchived() bool { return c.ArchivedDate != nil }

// SubTitle mirrors the per-type subTitle getters used by basic search.
func (c *CipherView) SubTitle() string {
	switch c.Type {
	case CipherTypeLogin:
		if c.Login != nil {
			return deref(c.Login.Username)
		}
	case CipherTypeCard:
		brand := deref(c.Typed["brand"])
		num := deref(c.Typed["number"])
		sub := brand
		if len(num) >= 4 {
			if sub != "" {
				sub += ", "
			}
			count := 4
			if len(num) >= 5 && (strings.HasPrefix(num, "34") || strings.HasPrefix(num, "37")) {
				count = 5
			}
			sub += "*" + num[len(num)-count:]
		}
		return sub
	case CipherTypeIdentity:
		fn, ln := c.Typed["firstName"], c.Typed["lastName"]
		parts := []string{}
		if fn != nil {
			parts = append(parts, *fn)
		}
		if ln != nil {
			parts = append(parts, *ln)
		}
		return strings.Join(parts, " ")
	case CipherTypeSSHKey:
		return deref(c.Typed["keyFingerprint"])
	case CipherTypeBankAccount:
		return deref(c.Typed["bankName"])
	case CipherTypeDriversLicense:
		name := strings.TrimSpace(deref(c.Typed["firstName"]) + " " + deref(c.Typed["lastName"]))
		st := deref(c.Typed["issuingState"])
		if name != "" && st != "" {
			return name + ", " + st
		}
		if name != "" {
			return name
		}
		return st
	case CipherTypePassport:
		return strings.TrimSpace(deref(c.Typed["givenName"]) + " " + deref(c.Typed["surname"]))
	}
	return ""
}

func decStr(key *crypto.SymmetricKey, s *string) *string {
	if s == nil {
		return nil
	}
	if *s == "" {
		return strPtr("")
	}
	v, err := crypto.DecryptToString(key, *s)
	if err != nil {
		return strPtr(decryptError)
	}
	return &v
}

func decStrAny(key *crypto.SymmetricKey, v any) *string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return decStr(key, &s)
}

func rawToString(r json.RawMessage) *string {
	if len(r) == 0 || string(r) == "null" {
		return nil
	}
	var s string
	if json.Unmarshal(r, &s) == nil {
		return &s
	}
	var n json.Number
	if json.Unmarshal(r, &n) == nil {
		v := n.String()
		return &v
	}
	return nil
}

func getCI(m map[string]any, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}

// DecryptCipher decrypts with the user or organization key (vaultKey).
func DecryptCipher(d *CipherData, vaultKey *crypto.SymmetricKey) *CipherView {
	v := &CipherView{
		ID:                  d.ID,
		OrganizationID:      d.OrganizationID,
		FolderID:            d.FolderID,
		Type:                d.Type,
		Favorite:            d.Favorite,
		Reprompt:            d.Reprompt,
		Key:                 d.Key,
		CollectionIDs:       d.CollectionIDs,
		RevisionDate:        ParseTime(&d.RevisionDate),
		CreationDate:        ParseTime(d.CreationDate),
		DeletedDate:         ParseTime(d.DeletedDate),
		ArchivedDate:        ParseTime(d.ArchivedDate),
		Edit:                d.CanEdit(),
		ViewPassword:        d.CanViewPassword(),
		Permissions:         d.Permissions,
		OrganizationUseTotp: d.OrganizationUseTotp,
	}
	if v.CollectionIDs == nil {
		v.CollectionIDs = []string{}
	}
	key := vaultKey
	if d.Key != nil && *d.Key != "" && vaultKey != nil {
		if ck, err := crypto.DecryptToKey(vaultKey, *d.Key); err == nil {
			key = ck
		} else {
			key = nil
		}
	}
	v.Name = deref(decStr(key, &d.Name))
	v.Notes = decStr(key, d.Notes)

	switch d.Type {
	case CipherTypeLogin:
		if d.Login != nil {
			l := &LoginView{
				Username:             decStr(key, d.Login.Username),
				Password:             decStr(key, d.Login.Password),
				Totp:                 decStr(key, d.Login.Totp),
				PasswordRevisionDate: ParseTime(d.Login.PasswordRevisionDate),
				AutofillOnPageLoad:   d.Login.AutofillOnPageLoad,
			}
			if d.Login.URIs != nil {
				l.URIs = make([]LoginURIView, 0, len(d.Login.URIs))
				for _, u := range d.Login.URIs {
					l.URIs = append(l.URIs, LoginURIView{URI: decStr(key, u.URI), Match: u.Match})
				}
			}
			if d.Login.Fido2Credentials != nil {
				l.Fido2Credentials = make([]Fido2CredentialView, 0, len(d.Login.Fido2Credentials))
				for _, f := range d.Login.Fido2Credentials {
					l.Fido2Credentials = append(l.Fido2Credentials, Fido2CredentialView{
						CredentialID:    deref(decStr(key, f.CredentialID)),
						KeyType:         deref(decStr(key, f.KeyType)),
						KeyAlgorithm:    deref(decStr(key, f.KeyAlgorithm)),
						KeyCurve:        deref(decStr(key, f.KeyCurve)),
						KeyValue:        deref(decStr(key, f.KeyValue)),
						RpID:            deref(decStr(key, f.RpID)),
						UserHandle:      decStr(key, f.UserHandle),
						UserName:        decStr(key, f.UserName),
						Counter:         deref(decStr(key, f.Counter)),
						RpName:          decStr(key, f.RpName),
						UserDisplayName: decStr(key, f.UserDisplayName),
						Discoverable:    deref(decStr(key, f.Discoverable)),
						CreationDate:    ParseTime(f.CreationDate),
					})
				}
			}
			v.Login = l
		} else {
			v.Login = &LoginView{}
		}
	case CipherTypeSecureNote:
		t := 0
		if d.SecureNote != nil {
			t = d.SecureNote.Type
		}
		v.SecureNoteType = &t
	default:
		if _, fields := typedFields(d.Type); fields != nil {
			src := d.typedData()
			v.Typed = map[string]*string{}
			for _, f := range fields {
				if src != nil {
					v.Typed[f] = decStrAny(key, getCI(src, f))
				}
			}
		}
	}
	if d.Fields != nil {
		v.Fields = make([]FieldView, 0, len(d.Fields))
		for _, f := range d.Fields {
			v.Fields = append(v.Fields, FieldView{Name: decStr(key, f.Name), Value: decStr(key, f.Value), Type: f.Type, LinkedID: f.LinkedID})
		}
	}
	if d.PasswordHistory != nil {
		v.PasswordHistory = make([]PasswordHistoryView, 0, len(d.PasswordHistory))
		for _, ph := range d.PasswordHistory {
			v.PasswordHistory = append(v.PasswordHistory, PasswordHistoryView{
				Password:     deref(decStr(key, &ph.Password)),
				LastUsedDate: ParseTime(&ph.LastUsedDate),
			})
		}
	}
	if d.Attachments != nil {
		v.Attachments = make([]AttachmentView, 0, len(d.Attachments))
		for _, a := range d.Attachments {
			av := AttachmentView{ID: a.ID, URL: a.URL, FileName: decStr(key, a.FileName), EncKey: a.Key, Size: rawToString(a.Size), SizeName: a.SizeName}
			if a.Key != nil && *a.Key != "" && key != nil {
				if ak, err := crypto.DecryptToKey(key, *a.Key); err == nil {
					av.Key = ak
				}
			}
			v.Attachments = append(v.Attachments, av)
		}
	}
	v.search = v.newSearchIndex()
	return v
}

// ToCLI renders the cipher like the CLI's CipherResponse. Key order follows
// the TypeScript class field initialization order and undefined values are
// omitted, exactly as JSON.stringify does in the official CLI.
func (c *CipherView) ToCLI() *OMap {
	m := NewOMap().
		Set("type", c.Type).
		Set("name", c.Name).
		Set("favorite", c.Favorite).
		Set("reprompt", c.Reprompt).
		Set("id", c.ID).
		Set("collectionIds", nonNilStrings(c.CollectionIDs)).
		Set("object", "item")
	setOpt(m, "organizationId", c.OrganizationID)
	setOpt(m, "folderId", c.FolderID)
	setOpt(m, "notes", c.Notes)
	setOpt(m, "key", c.Key)

	fields := make([]*OMap, 0, len(c.Fields))
	for _, f := range c.Fields {
		fm := NewOMap().Set("type", f.Type)
		setOpt(fm, "name", f.Name)
		if !c.ViewPassword && f.Type == FieldTypeHidden {
			fm.Set("value", nil)
		} else {
			setOpt(fm, "value", f.Value)
		}
		if f.LinkedID != nil {
			fm.Set("linkedId", *f.LinkedID)
		}
		fields = append(fields, fm)
	}
	m.Set("fields", fields)

	switch c.Type {
	case CipherTypeLogin:
		m.Set("login", c.loginCLI())
	case CipherTypeSecureNote:
		t := 0
		if c.SecureNoteType != nil {
			t = *c.SecureNoteType
		}
		m.Set("secureNote", NewOMap().Set("type", t))
	default:
		if name, keys := typedFields(c.Type); keys != nil {
			sub := NewOMap()
			for _, f := range keys {
				if c.Type == CipherTypeSSHKey {
					sub.Set(f, deref(c.Typed[f]))
				} else {
					setOpt(sub, f, c.Typed[f])
				}
			}
			m.Set(name, sub)
		}
	}
	if c.ViewPassword {
		ph := make([]*OMap, 0, len(c.PasswordHistory))
		for _, h := range c.PasswordHistory {
			ph = append(ph, NewOMap().Set("lastUsedDate", JSTime(h.LastUsedDate)).Set("password", h.Password))
		}
		m.Set("passwordHistory", ph)
	}
	if c.CreationDate != nil {
		m.Set("creationDate", JSTime(c.CreationDate))
	}
	m.Set("revisionDate", JSTime(c.RevisionDate))
	if c.DeletedDate != nil {
		m.Set("deletedDate", JSTime(c.DeletedDate))
	}
	if c.ArchivedDate != nil {
		m.Set("archivedDate", JSTime(c.ArchivedDate))
	}
	atts := make([]*OMap, 0, len(c.Attachments))
	for _, a := range c.Attachments {
		am := NewOMap().Set("id", a.ID)
		setOpt(am, "fileName", a.FileName)
		setOpt(am, "size", a.Size)
		setOpt(am, "sizeName", a.SizeName)
		setOpt(am, "url", a.URL)
		atts = append(atts, am)
	}
	m.Set("attachments", atts)
	return m
}

func setOpt(m *OMap, k string, v *string) {
	if v != nil {
		m.Set(k, *v)
	}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (c *CipherView) loginCLI() *OMap {
	l := c.Login
	if l == nil {
		l = &LoginView{}
	}
	m := NewOMap()
	uris := make([]*OMap, 0, len(l.URIs))
	for _, u := range l.URIs {
		um := NewOMap()
		setOpt(um, "uri", u.URI)
		if u.Match != nil {
			um.Set("match", *u.Match)
		}
		uris = append(uris, um)
	}
	m.Set("uris", uris)
	fcs := make([]*OMap, 0, len(l.Fido2Credentials))
	for _, f := range l.Fido2Credentials {
		fm := NewOMap().
			Set("credentialId", f.CredentialID).Set("keyType", f.KeyType).Set("keyAlgorithm", f.KeyAlgorithm).
			Set("keyCurve", f.KeyCurve).Set("keyValue", f.KeyValue).Set("rpId", f.RpID).
			Set("counter", f.Counter).Set("discoverable", f.Discoverable).Set("creationDate", JSTime(f.CreationDate))
		setOpt(fm, "userHandle", f.UserHandle)
		setOpt(fm, "userName", f.UserName)
		setOpt(fm, "rpName", f.RpName)
		setOpt(fm, "userDisplayName", f.UserDisplayName)
		fcs = append(fcs, fm)
	}
	m.Set("fido2Credentials", fcs)
	setOpt(m, "username", l.Username)
	if c.ViewPassword {
		setOpt(m, "password", l.Password)
		setOpt(m, "totp", l.Totp)
	} else {
		m.Set("password", nil)
		m.Set("totp", nil)
	}
	m.Set("passwordRevisionDate", JSTime(l.PasswordRevisionDate))
	return m
}

// FolderView is a decrypted folder.
type FolderView struct {
	ID           string
	Name         string
	RevisionDate *time.Time
}

func (f *FolderView) ToCLI() *OMap {
	return NewOMap().Set("name", f.Name).Set("object", "folder").Set("id", f.ID)
}

// CollectionView is a decrypted collection.
type CollectionView struct {
	ID             string
	OrganizationID string
	Name           string
	ExternalID     *string
	ReadOnly       bool
	HidePasswords  bool
	Manage         bool
}

// ToCLI renders a collection; externalId is omitted when unknown, as for
// synced collections in the CLI, unless explicitNullExternalID is set.
func (c *CollectionView) ToCLI(object string, explicitNullExternalID bool) *OMap {
	m := NewOMap().Set("object", object).Set("id", c.ID).Set("organizationId", c.OrganizationID).Set("name", c.Name)
	if c.ExternalID != nil || explicitNullExternalID {
		m.Set("externalId", nullable(c.ExternalID))
	}
	return m
}

func DecryptCollection(d *CollectionData, orgKey *crypto.SymmetricKey) *CollectionView {
	return &CollectionView{
		ID: d.ID, OrganizationID: d.OrganizationID, Name: deref(decStr(orgKey, &d.Name)),
		ExternalID: d.ExternalID, ReadOnly: d.ReadOnly, HidePasswords: d.HidePasswords, Manage: d.Manage,
	}
}

// SendView is a decrypted send.
type SendView struct {
	ID             string
	AccessID       string
	Name           *string
	Notes          *string
	KeyMaterial    []byte
	CryptoKey      *crypto.SymmetricKey
	Type           int
	Text           *string
	TextHidden     bool
	FileID         *string
	FileName       *string
	FileSize       *string
	FileSizeName   *string
	MaxAccessCount *int
	AccessCount    int
	RevisionDate   *time.Time
	DeletionDate   *time.Time
	ExpirationDate *time.Time
	Password       *string // server-side hash
	Emails         []string
	Disabled       bool
	HideEmail      bool
	AuthType       *int
}

func DecryptSend(d *SendData, userKey *crypto.SymmetricKey) *SendView {
	v := &SendView{
		ID: d.ID, AccessID: d.AccessID, Type: d.Type, MaxAccessCount: d.MaxAccessCount, AccessCount: d.AccessCount,
		RevisionDate: ParseTime(d.RevisionDate), DeletionDate: ParseTime(d.DeletionDate),
		ExpirationDate: ParseTime(d.ExpirationDate), Password: d.Password, Disabled: d.Disabled,
		HideEmail: d.HideEmail, AuthType: d.AuthType, Emails: []string{},
	}
	if d.Emails != nil && *d.Emails != "" {
		for _, e := range strings.Split(*d.Emails, ",") {
			if e = strings.TrimSpace(e); e != "" {
				v.Emails = append(v.Emails, e)
			}
		}
	}
	if es, err := crypto.ParseEncString(d.Key); err == nil {
		if mat, err := es.Decrypt(userKey); err == nil {
			v.KeyMaterial = mat
			v.CryptoKey, _ = crypto.DeriveSendKey(mat)
		}
	}
	v.Name = decStr(v.CryptoKey, d.Name)
	v.Notes = decStr(v.CryptoKey, d.Notes)
	if d.Text != nil {
		v.Text = decStr(v.CryptoKey, d.Text.Text)
		v.TextHidden = d.Text.Hidden
	}
	if d.File != nil {
		v.FileID = d.File.ID
		v.FileName = decStr(v.CryptoKey, d.File.FileName)
		v.FileSize = rawToString(d.File.Size)
		v.FileSizeName = d.File.SizeName
	}
	return v
}

// ToCLI renders the send like the CLI's SendResponse.
func (s *SendView) ToCLI(sendURL string) *OMap {
	urlKey := base64.RawURLEncoding.EncodeToString(s.KeyMaterial)
	m := NewOMap().Set("object", "send").Set("id", s.ID).Set("accessId", s.AccessID).
		Set("accessUrl", sendURL+s.AccessID+"/"+urlKey).
		Set("name", nullable(s.Name)).Set("notes", nullable(s.Notes)).
		Set("key", base64.StdEncoding.EncodeToString(s.KeyMaterial)).Set("type", s.Type)
	if s.MaxAccessCount != nil {
		m.Set("maxAccessCount", *s.MaxAccessCount)
	} else {
		m.Set("maxAccessCount", nil)
	}
	m.Set("accessCount", s.AccessCount).
		Set("revisionDate", JSTime(s.RevisionDate)).
		Set("deletionDate", JSTime(s.DeletionDate)).
		Set("expirationDate", JSTime(s.ExpirationDate)).
		Set("passwordSet", s.Password != nil).
		Set("emails", s.Emails).
		Set("disabled", s.Disabled).
		Set("hideEmail", s.HideEmail)
	if s.AuthType != nil {
		m.Set("authType", *s.AuthType)
	}
	if s.Type == SendTypeText {
		m.Set("text", NewOMap().Set("text", nullable(s.Text)).Set("hidden", s.TextHidden))
	}
	if s.Type == SendTypeFile {
		m.Set("file", NewOMap().Set("id", nullable(s.FileID)).Set("size", nullable(s.FileSize)).
			Set("sizeName", nullable(s.FileSizeName)).Set("fileName", nullable(s.FileName)))
	}
	return m
}

// uriChecksum is the encrypted base64 SHA-256 of the URI stored alongside login URIs.
func uriChecksum(key *crypto.SymmetricKey, uri string) (string, error) {
	sum := sha256.Sum256([]byte(uri))
	return crypto.EncryptString(key, base64.StdEncoding.EncodeToString(sum[:]))
}
