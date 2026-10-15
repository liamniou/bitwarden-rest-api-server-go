package vault

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/api"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/crypto"
)

var (
	ErrNotLoggedIn = errors.New("You are not logged in.")
	ErrLocked      = errors.New("Vault is locked.")
)

// Vault holds the account session, the encrypted server state and the
// decrypted views. Decryption happens once per sync/unlock, so reads are
// served from memory without touching disk or re-running any crypto.
type Vault struct {
	Client *api.Client
	Log    *slog.Logger

	mu sync.RWMutex

	userID     string
	email      string
	kdf        crypto.KdfConfig
	salt       string
	encUserKey string
	loggedIn   bool

	userKey    *crypto.SymmetricKey
	privateKey *rsa.PrivateKey
	orgKeys    map[string]*crypto.SymmetricKey

	profile     Profile
	cipherData  map[string]*CipherData
	cipherOrder []string
	folderData  []FolderData
	collData    []CollectionData
	sendData    []SendData
	policies    []PolicyData
	domains     *DomainsData
	lastSync    *time.Time
	lastRev     time.Time

	ciphers     map[string]*CipherView
	folders     []*FolderView
	collections []*CollectionView
	sends       []*SendView

	syncMu sync.Mutex
}

func New(client *api.Client, log *slog.Logger) *Vault {
	return &Vault{Client: client, Log: log, cipherData: map[string]*CipherData{}, ciphers: map[string]*CipherView{}}
}

// LoginAPIKey authenticates with a personal API key.
func (v *Vault) LoginAPIKey(ctx context.Context, clientID, clientSecret string) error {
	tr, err := v.Client.LoginAPIKey(ctx, clientID, clientSecret)
	if err != nil {
		return err
	}
	if tr.ApiUseKeyConnector {
		return errors.New("Key Connector accounts are not supported")
	}
	return v.applyToken(tr, "")
}

// LoginPassword authenticates with email and master password.
func (v *Vault) LoginPassword(ctx context.Context, email, password, tfToken, tfProvider string) error {
	pre, err := v.Client.Prelogin(ctx, email)
	if err != nil {
		return err
	}
	kdf := crypto.KdfConfig{Type: pre.Kdf, Iterations: pre.KdfIterations}
	if pre.KdfMemory != nil {
		kdf.Memory = *pre.KdfMemory
	}
	if pre.KdfParallelism != nil {
		kdf.Parallelism = *pre.KdfParallelism
	}
	salt := pre.Salt
	if salt == "" {
		salt = crypto.NormalizeEmail(email)
	}
	mk, err := crypto.MakeMasterKey(password, salt, kdf)
	if err != nil {
		return err
	}
	hash, err := crypto.MasterPasswordHash(mk, password)
	if err != nil {
		return err
	}
	tr, err := v.Client.LoginPassword(ctx, crypto.NormalizeEmail(email), hash, tfToken, tfProvider)
	if err != nil {
		return err
	}
	return v.applyToken(tr, email)
}

func (v *Vault) applyToken(tr *api.TokenResponse, email string) error {
	claims, err := api.JWTClaims(tr.AccessToken)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.userID, _ = claims["sub"].(string)
	if e, ok := claims["email"].(string); ok && e != "" {
		v.email = e
	} else if email != "" {
		v.email = email
	}
	v.encUserKey = tr.Key
	if tr.Kdf != nil {
		v.kdf = crypto.KdfConfig{Type: *tr.Kdf}
		if tr.KdfIterations != nil {
			v.kdf.Iterations = *tr.KdfIterations
		}
		if tr.KdfMemory != nil {
			v.kdf.Memory = *tr.KdfMemory
		}
		if tr.KdfParallelism != nil {
			v.kdf.Parallelism = *tr.KdfParallelism
		}
	}
	if len(tr.UserDecryptionOptions) > 0 {
		var udo struct {
			MasterPasswordUnlock *struct {
				Kdf struct {
					KdfType     int  `json:"KdfType"`
					Iterations  int  `json:"Iterations"`
					Memory      *int `json:"Memory"`
					Parallelism *int `json:"Parallelism"`
				} `json:"Kdf"`
				MasterKeyEncryptedUserKey string `json:"MasterKeyEncryptedUserKey"`
				Salt                      string `json:"Salt"`
			} `json:"MasterPasswordUnlock"`
		}
		if json.Unmarshal(tr.UserDecryptionOptions, &udo) == nil && udo.MasterPasswordUnlock != nil {
			mp := udo.MasterPasswordUnlock
			v.salt = mp.Salt
			if mp.MasterKeyEncryptedUserKey != "" {
				v.encUserKey = mp.MasterKeyEncryptedUserKey
			}
			if mp.Kdf.Iterations > 0 {
				v.kdf = crypto.KdfConfig{Type: mp.Kdf.KdfType, Iterations: mp.Kdf.Iterations}
				if mp.Kdf.Memory != nil {
					v.kdf.Memory = *mp.Kdf.Memory
				}
				if mp.Kdf.Parallelism != nil {
					v.kdf.Parallelism = *mp.Kdf.Parallelism
				}
			}
		}
	}
	if v.encUserKey == "" {
		return errors.New("account has no master-password-protected user key (SSO/TDE/Key Connector accounts are not supported)")
	}
	v.profile.PrivateKey = tr.PrivateKey
	v.loggedIn = true
	return nil
}

// Unlock derives the user key from the master password and decrypts the vault.
func (v *Vault) Unlock(password string) error {
	v.mu.RLock()
	loggedIn := v.loggedIn
	email, salt, kdf, encUserKey := v.email, v.salt, v.kdf, v.encUserKey
	v.mu.RUnlock()
	if !loggedIn {
		return ErrNotLoggedIn
	}
	if salt == "" {
		salt = crypto.NormalizeEmail(email)
	}
	mk, err := crypto.MakeMasterKey(password, salt, kdf)
	if err != nil {
		return err
	}
	uk, err := crypto.DecryptUserKeyWithMasterKey(mk, encUserKey)
	if err != nil {
		return err
	}
	if len(uk.Mac) == 0 {
		return errors.New("legacy accounts without a MAC key must be migrated in the web vault first")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.userKey = uk
	v.rebuildKeysLocked()
	v.decryptAllLocked()
	return nil
}

// Lock drops every key and decrypted value from memory.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.userKey = nil
	v.privateKey = nil
	v.orgKeys = nil
	v.ciphers = map[string]*CipherView{}
	v.cipherOrder = nil
	v.folders, v.collections, v.sends = nil, nil, nil
}

func (v *Vault) rebuildKeysLocked() {
	v.privateKey = nil
	v.orgKeys = map[string]*crypto.SymmetricKey{}
	if v.userKey == nil {
		return
	}
	wrapped := v.profile.PrivateKey
	if v.profile.AccountKeys != nil && v.profile.AccountKeys.PublicKeyEncryptionKeyPair != nil &&
		v.profile.AccountKeys.PublicKeyEncryptionKeyPair.WrappedPrivateKey != "" {
		wrapped = v.profile.AccountKeys.PublicKeyEncryptionKeyPair.WrappedPrivateKey
	}
	if wrapped != "" {
		if es, err := crypto.ParseEncString(wrapped); err == nil {
			if der, err := es.Decrypt(v.userKey); err == nil {
				if pk, err := crypto.ParsePrivateKey(der); err == nil {
					v.privateKey = pk
				} else {
					v.Log.Warn("could not parse private key", "err", err)
				}
			} else {
				v.Log.Warn("could not decrypt private key", "err", err)
			}
		}
	}
	if v.privateKey == nil {
		return
	}
	for _, o := range v.profile.Organizations {
		if o.Key == "" {
			continue
		}
		if k, err := crypto.DecapsulateKey(v.privateKey, o.Key); err == nil {
			v.orgKeys[o.ID] = k
		} else {
			v.Log.Warn("could not decrypt organization key", "org", o.ID, "err", err)
		}
	}
	providerKeys := map[string]*crypto.SymmetricKey{}
	for _, p := range v.profile.Providers {
		if k, err := crypto.DecapsulateKey(v.privateKey, p.Key); err == nil {
			providerKeys[p.ID] = k
		}
	}
	for _, po := range v.profile.ProviderOrganizations {
		if _, ok := v.orgKeys[po.ID]; ok || po.ProviderID == nil {
			continue
		}
		if pk := providerKeys[*po.ProviderID]; pk != nil {
			if k, err := crypto.DecryptToKey(pk, po.Key); err == nil {
				v.orgKeys[po.ID] = k
			}
		}
	}
}

func (v *Vault) vaultKeyLocked(orgID *string) *crypto.SymmetricKey {
	if orgID != nil && *orgID != "" {
		return v.orgKeys[*orgID]
	}
	return v.userKey
}

func (v *Vault) decryptAllLocked() {
	if v.userKey == nil {
		return
	}
	v.ciphers = make(map[string]*CipherView, len(v.cipherData))
	for id, d := range v.cipherData {
		v.ciphers[id] = DecryptCipher(d, v.vaultKeyLocked(d.OrganizationID))
	}
	v.resortCiphersLocked()
	v.folders = make([]*FolderView, 0, len(v.folderData))
	for i := range v.folderData {
		f := &v.folderData[i]
		v.folders = append(v.folders, &FolderView{ID: f.ID, Name: deref(decStr(v.userKey, &f.Name)), RevisionDate: ParseTime(&f.RevisionDate)})
	}
	sortByName(v.folders, func(f *FolderView) string { return f.Name })
	v.collections = make([]*CollectionView, 0, len(v.collData))
	for i := range v.collData {
		c := &v.collData[i]
		v.collections = append(v.collections, DecryptCollection(c, v.orgKeys[c.OrganizationID]))
	}
	sortByName(v.collections, func(c *CollectionView) string { return c.Name })
	v.sends = make([]*SendView, 0, len(v.sendData))
	for i := range v.sendData {
		v.sends = append(v.sends, DecryptSend(&v.sendData[i], v.userKey))
	}
}

// newCollator mirrors the CLI's Intl.Collator(locale, {numeric: true, sensitivity: "base"}).
func newCollator() *collate.Collator {
	return collate.New(language.English, collate.Numeric, collate.Loose)
}

// SortByName sorts like Utils.getSortFunction(i18nService, "name").
func SortByName[T any](s []T, name func(T) string) { sortByName(s, name) }

func sortByName[T any](s []T, name func(T) string) {
	col := newCollator()
	sort.SliceStable(s, func(i, j int) bool {
		return col.CompareString(name(s[i]), name(s[j])) < 0
	})
}

// resortCiphersLocked implements cipherService.getLocaleSortingFunction.
func (v *Vault) resortCiphersLocked() {
	col := newCollator()
	ids := make([]string, 0, len(v.ciphers))
	for id := range v.ciphers {
		ids = append(ids, id)
	}
	sort.SliceStable(ids, func(i, j int) bool {
		a, b := v.ciphers[ids[i]], v.ciphers[ids[j]]
		r := col.CompareString(a.Name, b.Name)
		if r == 0 && a.Type == CipherTypeLogin && b.Type == CipherTypeLogin && a.Login != nil && b.Login != nil {
			r = col.CompareString(a.Name+deref(a.Login.Username), b.Name+deref(b.Login.Username))
		}
		if r == 0 {
			return ids[i] < ids[j]
		}
		return r < 0
	})
	v.cipherOrder = ids
}

// Sync pulls the vault from the server. Without force it first checks the
// account revision date and skips the full download when nothing changed.
// The comparison uses server-reported revision dates only, so clock skew
// between this host and the server can't hide changes.
func (v *Vault) Sync(ctx context.Context, force bool) error {
	v.syncMu.Lock()
	defer v.syncMu.Unlock()
	v.mu.RLock()
	loggedIn, lastSync, lastRev := v.loggedIn, v.lastSync, v.lastRev
	v.mu.RUnlock()
	if !loggedIn {
		return ErrNotLoggedIn
	}
	var rev time.Time
	var ms json.Number
	if err := v.Client.Do(ctx, "GET", "/accounts/revision-date", nil, &ms); err == nil {
		if n, err := ms.Int64(); err == nil && n > 0 {
			rev = time.UnixMilli(n)
		}
	}
	if !force && lastSync != nil && !rev.IsZero() && !lastRev.IsZero() && !rev.After(lastRev) {
		now := time.Now().UTC()
		v.mu.Lock()
		v.lastSync = &now
		v.mu.Unlock()
		return nil
	}
	var s SyncResponse
	if err := v.Client.Do(ctx, "GET", "/sync", nil, &s); err != nil {
		return err
	}
	now := time.Now().UTC()
	v.mu.Lock()
	defer v.mu.Unlock()
	v.applySyncLocked(&s)
	v.lastSync = &now
	v.lastRev = rev
	return nil
}

func (v *Vault) applySyncLocked(s *SyncResponse) {
	v.profile = s.Profile
	if s.Profile.ID != "" {
		v.userID = s.Profile.ID
	}
	if s.Profile.Email != "" {
		v.email = s.Profile.Email
	}
	if s.Profile.Key != "" {
		v.encUserKey = s.Profile.Key
	}
	if s.UserDecryption != nil && s.UserDecryption.MasterPasswordUnlock != nil {
		mp := s.UserDecryption.MasterPasswordUnlock
		if mp.Salt != "" {
			v.salt = mp.Salt
		}
		if mp.MasterKeyEncryptedUserKey != "" {
			v.encUserKey = mp.MasterKeyEncryptedUserKey
		}
		if mp.Kdf != nil && mp.Kdf.Iterations > 0 {
			v.kdf = crypto.KdfConfig{Type: mp.Kdf.KdfType, Iterations: mp.Kdf.Iterations}
			if mp.Kdf.Memory != nil {
				v.kdf.Memory = *mp.Kdf.Memory
			}
			if mp.Kdf.Parallelism != nil {
				v.kdf.Parallelism = *mp.Kdf.Parallelism
			}
		}
	}
	v.cipherData = make(map[string]*CipherData, len(s.Ciphers))
	for i := range s.Ciphers {
		c := &s.Ciphers[i]
		v.cipherData[c.ID] = c
	}
	v.folderData = s.Folders
	v.collData = s.Collections
	v.sendData = s.Sends
	v.policies = s.Policies
	if s.Domains != nil {
		v.domains = s.Domains
	}
	if v.userKey != nil {
		v.rebuildKeysLocked()
		v.decryptAllLocked()
	}
}

// Status mirrors `bw status`.
type Status struct {
	ServerURL *string
	LastSync  *time.Time
	UserEmail string
	UserID    string
	Status    string
}

func (v *Vault) Status() Status {
	v.mu.RLock()
	defer v.mu.RUnlock()
	st := Status{LastSync: v.lastSync}
	if v.Client.URLs.Base != "" {
		b := v.Client.URLs.Base
		st.ServerURL = &b
	}
	switch {
	case !v.loggedIn:
		st.Status = "unauthenticated"
		return st
	case v.userKey == nil:
		st.Status = "locked"
	default:
		st.Status = "unlocked"
	}
	st.UserEmail, st.UserID = v.email, v.userID
	return st
}

// CheckUnlocked implements errorIfLocked.
func (v *Vault) CheckUnlocked() error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !v.loggedIn {
		return ErrNotLoggedIn
	}
	if v.userKey == nil {
		return ErrLocked
	}
	return nil
}

func (v *Vault) LastSync() *time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastSync
}

func (v *Vault) UserID() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.userID
}

// HasPremium mirrors hasPremiumFromAnySource$.
func (v *Vault) HasPremium() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.hasPremiumLocked()
}

func (v *Vault) hasPremiumLocked() bool {
	if v.profile.Premium || v.profile.PremiumFromOrganization {
		return true
	}
	for _, o := range v.profile.Organizations {
		if o.UsersGetPremium && o.Enabled {
			return true
		}
	}
	if tok := v.Client.CurrentAccessToken(); tok != "" {
		if c, err := api.JWTClaims(tok); err == nil {
			if p, ok := c["premium"].(bool); ok && p {
				return true
			}
		}
	}
	return false
}

// --- read accessors (callers receive pointers to immutable snapshots) ---

func (v *Vault) Ciphers() []*CipherView {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]*CipherView, 0, len(v.ciphers))
	for _, id := range v.cipherOrder {
		if c, ok := v.ciphers[id]; ok {
			out = append(out, c)
		}
	}
	return out
}

func (v *Vault) Cipher(id string) *CipherView {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.ciphers[id]
}

func (v *Vault) CipherData(id string) *CipherData {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.cipherData[id]
}

func (v *Vault) Folders() []*FolderView {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]*FolderView, 0, len(v.folders)+1)
	out = append(out, v.folders...)
	// The CLI always appends the virtual "No Folder" entry.
	out = append(out, &FolderView{Name: "No Folder"})
	return out
}

func (v *Vault) Folder(id string) *FolderView {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, f := range v.folders {
		if f.ID == id {
			return f
		}
	}
	return nil
}

func (v *Vault) Collections() []*CollectionView {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return append([]*CollectionView(nil), v.collections...)
}

func (v *Vault) Sends() []*SendView {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return append([]*SendView(nil), v.sends...)
}

func (v *Vault) Send(id string) *SendView {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, s := range v.sends {
		if s.ID == id {
			return s
		}
	}
	return nil
}

func (v *Vault) SendData(id string) *SendData {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for i := range v.sendData {
		if v.sendData[i].ID == id {
			return &v.sendData[i]
		}
	}
	return nil
}

// Organization is the member view of an organization.
type Organization struct {
	ID                 string
	Name               string
	Status             int
	Type               int
	Enabled            bool
	UseTotp            bool
	OrganizationUserID string
	Permissions        OrgPermissions
}

func (o *Organization) IsAdmin() bool {
	return o.Type == OrgUserTypeOwner || o.Type == OrgUserTypeAdmin
}
func (o *Organization) CanViewAllCollections() bool {
	return o.IsAdmin() || o.Permissions.EditAnyCollection || o.Permissions.DeleteAnyCollection
}
func (o *Organization) CanEditAllCiphers() bool {
	return o.IsAdmin() || o.Permissions.EditAnyCollection
}
func (o *Organization) CanManageUsersPassword() bool {
	return o.IsAdmin() || o.Permissions.ManageResetPassword
}

func (o *Organization) ToCLI() *OMap {
	return NewOMap().Set("object", "organization").Set("id", o.ID).Set("name", o.Name).
		Set("status", o.Status).Set("type", o.Type).Set("enabled", o.Enabled)
}

func (v *Vault) Organizations() []*Organization {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]*Organization, 0, len(v.profile.Organizations))
	for _, o := range v.profile.Organizations {
		out = append(out, &Organization{ID: o.ID, Name: o.Name, Status: o.Status, Type: o.Type, Enabled: o.Enabled,
			UseTotp: o.UseTotp, OrganizationUserID: o.OrganizationUserID, Permissions: o.Permissions})
	}
	sortByName(out, func(o *Organization) string { return o.Name })
	return out
}

func (v *Vault) Organization(id string) *Organization {
	for _, o := range v.Organizations() {
		if o.ID == id {
			return o
		}
	}
	return nil
}

func (v *Vault) OrgKey(orgID string) *crypto.SymmetricKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.orgKeys[orgID]
}

func (v *Vault) UserKey() *crypto.SymmetricKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.userKey
}

func (v *Vault) PublicKeyDER() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.privateKey == nil {
		return nil, errors.New("No public key available for the active user.")
	}
	return crypto.PublicKeyDER(v.privateKey)
}

func (v *Vault) PrivateKey() *rsa.PrivateKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.privateKey
}

// Policies returns enabled policies of a type that apply to the user.
// Owners and admins are exempt unless exemptAdmins is false.
func (v *Vault) Policies(policyType int, exemptAdmins bool) []PolicyData {
	v.mu.RLock()
	defer v.mu.RUnlock()
	orgs := map[string]ProfileOrganization{}
	for _, o := range v.profile.Organizations {
		orgs[o.ID] = o
	}
	var out []PolicyData
	for _, p := range v.policies {
		if p.Type != policyType || !p.Enabled {
			continue
		}
		o, ok := orgs[p.OrganizationID]
		if !ok || !o.Enabled || !o.UsePolicies || o.Status != OrgStatusConfirmed {
			continue
		}
		if exemptAdmins && (o.Type == OrgUserTypeOwner || o.Type == OrgUserTypeAdmin) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (v *Vault) Domains() *DomainsData {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.domains
}

// --- state mutation after successful server writes ---

func (v *Vault) upsertCipher(d *CipherData) *CipherView {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.cipherData[d.ID] = d
	view := DecryptCipher(d, v.vaultKeyLocked(d.OrganizationID))
	v.ciphers[d.ID] = view
	v.resortCiphersLocked()
	return view
}

func (v *Vault) removeCipher(id string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.cipherData, id)
	delete(v.ciphers, id)
	v.resortCiphersLocked()
}

func (v *Vault) upsertFolder(d FolderData) *FolderView {
	v.mu.Lock()
	defer v.mu.Unlock()
	replaced := false
	for i := range v.folderData {
		if v.folderData[i].ID == d.ID {
			v.folderData[i] = d
			replaced = true
		}
	}
	if !replaced {
		v.folderData = append(v.folderData, d)
	}
	fv := &FolderView{ID: d.ID, Name: deref(decStr(v.userKey, &d.Name)), RevisionDate: ParseTime(&d.RevisionDate)}
	nf := make([]*FolderView, 0, len(v.folders)+1)
	for _, f := range v.folders {
		if f.ID != d.ID {
			nf = append(nf, f)
		}
	}
	nf = append(nf, fv)
	sortByName(nf, func(f *FolderView) string { return f.Name })
	v.folders = nf
	return fv
}

func (v *Vault) removeFolder(id string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	fd := v.folderData[:0]
	for _, f := range v.folderData {
		if f.ID != id {
			fd = append(fd, f)
		}
	}
	v.folderData = fd
	nf := make([]*FolderView, 0, len(v.folders))
	for _, f := range v.folders {
		if f.ID != id {
			nf = append(nf, f)
		}
	}
	v.folders = nf
	for _, c := range v.cipherData {
		if c.FolderID != nil && *c.FolderID == id {
			c.FolderID = nil
		}
	}
	for id2, c := range v.ciphers {
		if c.FolderID != nil && *c.FolderID == id {
			cp := *c
			cp.FolderID = nil
			v.ciphers[id2] = &cp
		}
	}
}

func (v *Vault) upsertSend(d SendData) *SendView {
	v.mu.Lock()
	defer v.mu.Unlock()
	replaced := false
	for i := range v.sendData {
		if v.sendData[i].ID == d.ID {
			v.sendData[i] = d
			replaced = true
		}
	}
	if !replaced {
		v.sendData = append(v.sendData, d)
	}
	sv := DecryptSend(&d, v.userKey)
	ns := make([]*SendView, 0, len(v.sends)+1)
	inserted := false
	for _, s := range v.sends {
		if s.ID == d.ID {
			ns = append(ns, sv)
			inserted = true
		} else {
			ns = append(ns, s)
		}
	}
	if !inserted {
		ns = append(ns, sv)
	}
	v.sends = ns
	return sv
}

func (v *Vault) removeSend(id string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	sd := v.sendData[:0]
	for _, s := range v.sendData {
		if s.ID != id {
			sd = append(sd, s)
		}
	}
	v.sendData = sd
	ns := make([]*SendView, 0, len(v.sends))
	for _, s := range v.sends {
		if s.ID != id {
			ns = append(ns, s)
		}
	}
	v.sends = ns
}

// NewSessionKey produces a random value reported as the session key by /unlock.
func NewSessionKey() string {
	return base64.StdEncoding.EncodeToString(crypto.RandomBytes(64))
}
