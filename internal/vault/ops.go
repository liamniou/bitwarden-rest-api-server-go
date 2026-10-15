package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/api"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/crypto"
)

type listResponse[T any] struct {
	Data []T `json:"data"`
}

// --- ciphers ---

// CreateCipher implements cipherService.createWithServer.
func (v *Vault) CreateCipher(ctx context.Context, view *CipherView) (*CipherView, error) {
	v.mu.RLock()
	req, err := v.encryptCipherLocked(view, nil)
	v.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	var resp CipherData
	if len(view.CollectionIDs) > 0 {
		err = v.Client.Do(ctx, http.MethodPost, "/ciphers/create", map[string]any{"cipher": req, "collectionIds": view.CollectionIDs}, &resp)
	} else {
		err = v.Client.Do(ctx, http.MethodPost, "/ciphers", req, &resp)
	}
	if err != nil {
		return nil, err
	}
	if resp.CollectionIDs == nil {
		resp.CollectionIDs = view.CollectionIDs
	}
	return v.upsertCipher(&resp), nil
}

// UpdateCipher implements cipherService.updateWithServer including password history.
func (v *Vault) UpdateCipher(ctx context.Context, view *CipherView) (*CipherView, error) {
	v.mu.RLock()
	orig := v.cipherData[view.ID]
	existing := v.ciphers[view.ID]
	if orig == nil {
		v.mu.RUnlock()
		return nil, errors.New("Not found.")
	}
	adjustPasswordHistory(view, existing)
	var (
		req  any
		path = "/ciphers/" + view.ID
		err  error
	)
	if orig.CanEdit() {
		req, err = v.encryptCipherLocked(view, orig)
	} else {
		path += "/partial"
		req = map[string]any{"folderId": nullable(view.FolderID), "favorite": view.Favorite}
	}
	v.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	var resp CipherData
	if err := v.Client.Do(ctx, http.MethodPut, path, req, &resp); err != nil {
		return nil, err
	}
	if resp.CollectionIDs == nil {
		resp.CollectionIDs = view.CollectionIDs
	}
	return v.upsertCipher(&resp), nil
}

// SaveCipherCollections implements saveCollectionsWithServer.
func (v *Vault) SaveCipherCollections(ctx context.Context, id string, ids []string) (*CipherView, error) {
	if ids == nil {
		ids = []string{}
	}
	var resp struct {
		Unavailable bool        `json:"unavailable"`
		Cipher      *CipherData `json:"cipher"`
	}
	if err := v.Client.Do(ctx, http.MethodPut, "/ciphers/"+id+"/collections_v2", map[string]any{"collectionIds": ids}, &resp); err != nil {
		return nil, err
	}
	if resp.Unavailable || resp.Cipher == nil {
		v.removeCipher(id)
		return nil, nil
	}
	if resp.Cipher.CollectionIDs == nil {
		resp.Cipher.CollectionIDs = ids
	}
	return v.upsertCipher(resp.Cipher), nil
}

func (v *Vault) DeleteCipher(ctx context.Context, id string, permanent bool) error {
	if permanent {
		if err := v.Client.Do(ctx, http.MethodDelete, "/ciphers/"+id, nil, nil); err != nil {
			return err
		}
		v.removeCipher(id)
		return nil
	}
	if err := v.Client.Do(ctx, http.MethodPut, "/ciphers/"+id+"/delete", nil, nil); err != nil {
		return err
	}
	v.mutateCipherData(id, func(d *CipherData) {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		d.DeletedDate = &now
	})
	return nil
}

func (v *Vault) RestoreCipher(ctx context.Context, id string) error {
	var resp CipherData
	if err := v.Client.Do(ctx, http.MethodPut, "/ciphers/"+id+"/restore", nil, &resp); err != nil {
		return err
	}
	v.keepCollections(&resp)
	v.upsertCipher(&resp)
	return nil
}

func (v *Vault) ArchiveCipher(ctx context.Context, id string, archive bool) error {
	path := "/ciphers/archive"
	if !archive {
		path = "/ciphers/unarchive"
	}
	var resp listResponse[CipherData]
	if err := v.Client.Do(ctx, http.MethodPut, path, map[string]any{"ids": []string{id}}, &resp); err != nil {
		return err
	}
	for i := range resp.Data {
		v.keepCollections(&resp.Data[i])
		v.upsertCipher(&resp.Data[i])
	}
	return nil
}

func (v *Vault) keepCollections(d *CipherData) {
	if d.CollectionIDs != nil {
		return
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if old := v.cipherData[d.ID]; old != nil {
		d.CollectionIDs = old.CollectionIDs
	}
}

func (v *Vault) mutateCipherData(id string, fn func(*CipherData)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	d := v.cipherData[id]
	if d == nil {
		return
	}
	cp := *d
	fn(&cp)
	v.cipherData[id] = &cp
	v.ciphers[id] = DecryptCipher(&cp, v.vaultKeyLocked(cp.OrganizationID))
	v.resortCiphersLocked()
}

// ShareCipher moves a personal cipher into an organization.
func (v *Vault) ShareCipher(ctx context.Context, id, orgID string, collectionIDs []string) (*CipherView, error) {
	v.mu.RLock()
	orig := v.cipherData[id]
	existing := v.ciphers[id]
	orgKey := v.orgKeys[orgID]
	userKey := v.userKey
	v.mu.RUnlock()
	if orig == nil || existing == nil {
		return nil, errors.New("Not found.")
	}
	if orgKey == nil {
		return nil, errors.New("No encryption key for this organization.")
	}
	if existing.OrganizationID != nil {
		return nil, errors.New("Cipher is already associated with an organization.")
	}
	view := CloneCipherView(existing)
	adjustPasswordHistory(view, existing)

	var cipherKey *crypto.SymmetricKey
	if view.Key != nil && *view.Key != "" {
		ck, err := crypto.DecryptToKey(userKey, *view.Key)
		if err != nil {
			return nil, errors.New("Unable to decrypt the cipher key.")
		}
		cipherKey = ck
	} else {
		cipherKey = crypto.GenerateSymmetricKey()
		for _, a := range view.Attachments {
			if a.Key == nil {
				return nil, errors.New("This item has legacy attachments that must be re-uploaded before it can be moved to an organization.")
			}
		}
	}
	wrapped, err := crypto.Encrypt(orgKey, cipherKey.Bytes())
	if err != nil {
		return nil, err
	}
	ws := wrapped.String()
	view.Key = &ws
	view.OrganizationID = &orgID
	view.CollectionIDs = collectionIDs

	v.mu.RLock()
	req, err := v.encryptCipherLocked(view, orig)
	v.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	var resp CipherData
	if err := v.Client.Do(ctx, http.MethodPut, "/ciphers/"+id+"/share", map[string]any{"cipher": req, "collectionIds": collectionIDs}, &resp); err != nil {
		return nil, err
	}
	resp.CollectionIDs = collectionIDs
	return v.upsertCipher(&resp), nil
}

// --- attachments ---

func (v *Vault) cipherKeysLocked(d *CipherData) (*crypto.SymmetricKey, error) {
	vaultKey := v.vaultKeyLocked(d.OrganizationID)
	if vaultKey == nil {
		return nil, errors.New("No encryption key available for this item.")
	}
	if d.Key != nil && *d.Key != "" {
		return crypto.DecryptToKey(vaultKey, *d.Key)
	}
	return vaultKey, nil
}

// CreateAttachment implements saveAttachmentRawWithServer.
func (v *Vault) CreateAttachment(ctx context.Context, cipherID, fileName string, data []byte) (*CipherView, error) {
	v.mu.RLock()
	d := v.cipherData[cipherID]
	var key *crypto.SymmetricKey
	var err error
	if d != nil {
		key, err = v.cipherKeysLocked(d)
	}
	v.mu.RUnlock()
	if d == nil {
		return nil, errors.New("Not found.")
	}
	if err != nil {
		return nil, err
	}
	encName, err := crypto.EncryptString(key, fileName)
	if err != nil {
		return nil, err
	}
	attKey := crypto.GenerateSymmetricKey()
	wrappedAttKey, err := crypto.Encrypt(key, attKey.Bytes())
	if err != nil {
		return nil, err
	}
	encData, err := crypto.EncryptFile(attKey, data)
	if err != nil {
		return nil, err
	}
	var up struct {
		AttachmentID   string      `json:"attachmentId"`
		URL            string      `json:"url"`
		FileUploadType int         `json:"fileUploadType"`
		CipherResponse *CipherData `json:"cipherResponse"`
	}
	err = v.Client.Do(ctx, http.MethodPost, "/ciphers/"+cipherID+"/attachment/v2", map[string]any{
		"key": wrappedAttKey.String(), "fileName": encName, "fileSize": len(encData),
		"adminRequest": false, "lastKnownRevisionDate": d.RevisionDate,
	}, &up)
	if err != nil {
		return nil, err
	}
	switch up.FileUploadType {
	case 0:
		err = v.Client.DoMultipart(ctx, "/ciphers/"+cipherID+"/attachment/"+up.AttachmentID, encName, encData)
	case 1:
		if len(encData) > 256<<20 {
			err = errors.New("attachments larger than 256 MiB are not supported by this server")
		} else {
			err = v.Client.UploadAzure(ctx, up.URL, encData)
		}
	default:
		err = errors.New("Unknown file upload type")
	}
	if err != nil {
		_ = v.Client.Do(ctx, http.MethodDelete, "/ciphers/"+cipherID+"/attachment/"+up.AttachmentID, nil, nil)
		return nil, err
	}
	if up.CipherResponse == nil {
		return nil, errors.New("server did not return the updated cipher")
	}
	if up.CipherResponse.CollectionIDs == nil {
		up.CipherResponse.CollectionIDs = d.CollectionIDs
	}
	return v.upsertCipher(up.CipherResponse), nil
}

func (v *Vault) DeleteAttachment(ctx context.Context, cipherID, attachmentID string) error {
	var resp struct {
		Cipher *struct {
			RevisionDate string `json:"revisionDate"`
		} `json:"cipher"`
	}
	if err := v.Client.Do(ctx, http.MethodDelete, "/ciphers/"+cipherID+"/attachment/"+attachmentID, nil, &resp); err != nil {
		return err
	}
	v.mutateCipherData(cipherID, func(d *CipherData) {
		atts := make([]AttachmentData, 0, len(d.Attachments))
		for _, a := range d.Attachments {
			if a.ID != attachmentID {
				atts = append(atts, a)
			}
		}
		d.Attachments = atts
		if resp.Cipher != nil && resp.Cipher.RevisionDate != "" {
			d.RevisionDate = resp.Cipher.RevisionDate
		}
	})
	return nil
}

// DownloadAttachment fetches and decrypts an attachment.
func (v *Vault) DownloadAttachment(ctx context.Context, cipherID string, att AttachmentView) ([]byte, error) {
	url := deref(att.URL)
	var meta struct {
		URL string `json:"url"`
	}
	if err := v.Client.Do(ctx, http.MethodGet, "/ciphers/"+cipherID+"/attachment/"+att.ID, nil, &meta); err != nil {
		if !api.IsNotFound(err) {
			return nil, err
		}
	} else if meta.URL != "" {
		url = meta.URL
	}
	body, status, err := v.Client.Download(ctx, url)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("A %d error occurred while downloading the attachment.", status)
	}
	key := att.Key
	if key == nil {
		v.mu.RLock()
		d := v.cipherData[cipherID]
		if d != nil {
			key, err = v.cipherKeysLocked(d)
		}
		v.mu.RUnlock()
		if key == nil || err != nil {
			return nil, errors.New("An error occurred while saving the attachment.")
		}
	}
	plain, err := crypto.DecryptFile(key, body)
	if err != nil {
		return nil, errors.New("An error occurred while saving the attachment.")
	}
	return plain, nil
}

// --- folders ---

func (v *Vault) SaveFolder(ctx context.Context, id, name string) (*FolderView, error) {
	uk := v.UserKey()
	if uk == nil {
		return nil, ErrLocked
	}
	if name == "" {
		return nil, errors.New("Folder name is required")
	}
	encName, err := crypto.EncryptString(uk, name)
	if err != nil {
		return nil, err
	}
	var resp FolderData
	if id == "" {
		err = v.Client.Do(ctx, http.MethodPost, "/folders", map[string]any{"name": encName}, &resp)
	} else {
		err = v.Client.Do(ctx, http.MethodPut, "/folders/"+id, map[string]any{"name": encName}, &resp)
	}
	if err != nil {
		return nil, err
	}
	return v.upsertFolder(resp), nil
}

func (v *Vault) DeleteFolder(ctx context.Context, id string) error {
	if err := v.Client.Do(ctx, http.MethodDelete, "/folders/"+id, nil, nil); err != nil {
		return err
	}
	v.removeFolder(id)
	return nil
}

// --- organization collections ---

type SelectionReadOnly struct {
	ID            string `json:"id"`
	ReadOnly      bool   `json:"readOnly"`
	HidePasswords bool   `json:"hidePasswords"`
	Manage        bool   `json:"manage"`
}

type CollectionAccessDetails struct {
	ID             string              `json:"id"`
	OrganizationID string              `json:"organizationId"`
	Name           string              `json:"name"`
	ExternalID     *string             `json:"externalId"`
	Groups         []SelectionReadOnly `json:"groups"`
	Users          []SelectionReadOnly `json:"users"`
}

func (v *Vault) GetCollectionAccessDetails(ctx context.Context, orgID, id string) (*CollectionAccessDetails, error) {
	var resp CollectionAccessDetails
	err := v.Client.Do(ctx, http.MethodGet, "/organizations/"+orgID+"/collections/"+id+"/details", nil, &resp)
	return &resp, err
}

func (v *Vault) ListOrgCollections(ctx context.Context, orgID string, all bool) ([]CollectionData, error) {
	var resp listResponse[CollectionData]
	path := "/collections"
	if all {
		path = "/organizations/" + orgID + "/collections"
	}
	if err := v.Client.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	out := make([]CollectionData, 0, len(resp.Data))
	for _, c := range resp.Data {
		if c.OrganizationID == orgID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (v *Vault) SaveOrgCollection(ctx context.Context, orgID, id string, body map[string]any) (*CollectionAccessDetails, error) {
	var resp CollectionAccessDetails
	var err error
	if id == "" {
		err = v.Client.Do(ctx, http.MethodPost, "/organizations/"+orgID+"/collections", body, &resp)
	} else {
		err = v.Client.Do(ctx, http.MethodPut, "/organizations/"+orgID+"/collections/"+id, body, &resp)
	}
	return &resp, err
}

func (v *Vault) DeleteOrgCollection(ctx context.Context, orgID, id string) error {
	return v.Client.Do(ctx, http.MethodDelete, "/organizations/"+orgID+"/collections/"+id, nil, nil)
}

// --- organization members ---

type OrgUser struct {
	ID               string  `json:"id"`
	UserID           *string `json:"userId"`
	Email            string  `json:"email"`
	Name             *string `json:"name"`
	Status           int     `json:"status"`
	Type             int     `json:"type"`
	TwoFactorEnabled bool    `json:"twoFactorEnabled"`
}

func (v *Vault) ListOrgUsers(ctx context.Context, orgID string) ([]OrgUser, error) {
	var resp listResponse[OrgUser]
	err := v.Client.Do(ctx, http.MethodGet, "/organizations/"+orgID+"/users", nil, &resp)
	return resp.Data, err
}

func (v *Vault) GetOrgUser(ctx context.Context, orgID, id string) (*OrgUser, error) {
	var resp OrgUser
	err := v.Client.Do(ctx, http.MethodGet, "/organizations/"+orgID+"/users/"+id, nil, &resp)
	return &resp, err
}

func (v *Vault) UserPublicKey(ctx context.Context, userID string) ([]byte, error) {
	var resp struct {
		PublicKey string `json:"publicKey"`
	}
	if err := v.Client.Do(ctx, http.MethodGet, "/users/"+userID+"/public-key", nil, &resp); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.PublicKey)
}

func (v *Vault) ConfirmOrgUser(ctx context.Context, orgID, id string, body map[string]any) error {
	return v.Client.Do(ctx, http.MethodPost, "/organizations/"+orgID+"/users/"+id+"/confirm", body, nil)
}

// --- sends ---

func (v *Vault) SaveSend(ctx context.Context, id string, body map[string]any) (*SendView, error) {
	var resp SendData
	var err error
	if id == "" {
		err = v.Client.Do(ctx, http.MethodPost, "/sends", body, &resp)
	} else {
		err = v.Client.Do(ctx, http.MethodPut, "/sends/"+id, body, &resp)
	}
	if err != nil {
		return nil, err
	}
	return v.upsertSend(resp), nil
}

func (v *Vault) DeleteSend(ctx context.Context, id string) error {
	if err := v.Client.Do(ctx, http.MethodDelete, "/sends/"+id, nil, nil); err != nil {
		return err
	}
	v.removeSend(id)
	return nil
}

func (v *Vault) RemoveSendPassword(ctx context.Context, id string) (*SendView, error) {
	var resp SendData
	if err := v.Client.Do(ctx, http.MethodPut, "/sends/"+id+"/remove-password", nil, &resp); err != nil {
		return nil, err
	}
	return v.upsertSend(resp), nil
}

// --- device approvals (admin auth requests) ---

type PendingAuthRequest struct {
	ID                      string `json:"id"`
	UserID                  string `json:"userId"`
	OrganizationUserID      string `json:"organizationUserId"`
	Email                   string `json:"email"`
	PublicKey               string `json:"publicKey"`
	RequestDeviceIdentifier string `json:"requestDeviceIdentifier"`
	RequestDeviceType       string `json:"requestDeviceType"`
	RequestIPAddress        string `json:"requestIpAddress"`
	RequestCountryName      string `json:"requestCountryName"`
	CreationDate            string `json:"creationDate"`
}

func (v *Vault) ListPendingAuthRequests(ctx context.Context, orgID string) ([]PendingAuthRequest, error) {
	var resp listResponse[PendingAuthRequest]
	err := v.Client.Do(ctx, http.MethodGet, "/organizations/"+orgID+"/auth-requests", nil, &resp)
	return resp.Data, err
}

type resetPasswordDetails struct {
	OrganizationUserID  string `json:"organizationUserId"`
	ResetPasswordKey    string `json:"resetPasswordKey"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
}

func (v *Vault) encryptedUserKeyForDevice(orgID, devicePublicKey string, d resetPasswordDetails) (string, error) {
	orgKey := v.OrgKey(orgID)
	if orgKey == nil {
		return "", errors.New("No encryption key for this organization.")
	}
	es, err := crypto.ParseEncString(d.EncryptedPrivateKey)
	if err != nil {
		return "", err
	}
	der, err := es.Decrypt(orgKey)
	if err != nil {
		return "", err
	}
	orgPriv, err := crypto.ParsePrivateKey(der)
	if err != nil {
		return "", err
	}
	userKey, err := crypto.DecapsulateKey(orgPriv, d.ResetPasswordKey)
	if err != nil {
		return "", err
	}
	pub, err := base64.StdEncoding.DecodeString(devicePublicKey)
	if err != nil {
		return "", err
	}
	return crypto.EncapsulateKey(userKey, pub)
}

func (v *Vault) ApproveAuthRequest(ctx context.Context, orgID string, r PendingAuthRequest) error {
	var d resetPasswordDetails
	if err := v.Client.Do(ctx, http.MethodGet, "/organizations/"+orgID+"/users/"+r.OrganizationUserID+"/reset-password-details", nil, &d); err != nil {
		return err
	}
	if d.ResetPasswordKey == "" {
		return errors.New("The user must be enrolled in account recovery (password reset) in order for the request to be approved.")
	}
	key, err := v.encryptedUserKeyForDevice(orgID, r.PublicKey, d)
	if err != nil {
		return err
	}
	return v.Client.Do(ctx, http.MethodPost, "/organizations/"+orgID+"/auth-requests/"+r.ID,
		map[string]any{"requestApproved": true, "encryptedUserKey": key}, nil)
}

func (v *Vault) ApproveAuthRequests(ctx context.Context, orgID string, reqs []PendingAuthRequest) error {
	ids := make([]string, 0, len(reqs))
	for _, r := range reqs {
		ids = append(ids, r.OrganizationUserID)
	}
	var details listResponse[resetPasswordDetails]
	if err := v.Client.Do(ctx, http.MethodPost, "/organizations/"+orgID+"/users/account-recovery-details", map[string]any{"ids": ids}, &details); err != nil {
		return err
	}
	byUser := map[string]resetPasswordDetails{}
	for _, d := range details.Data {
		if d.ResetPasswordKey == "" {
			return errors.New("All users must be enrolled in account recovery (password reset) in order for the requests to be approved.")
		}
		byUser[d.OrganizationUserID] = d
	}
	if len(details.Data) == 0 {
		return errors.New("All users must be enrolled in account recovery (password reset) in order for the requests to be approved.")
	}
	items := make([]map[string]any, 0, len(reqs))
	for _, r := range reqs {
		d, ok := byUser[r.OrganizationUserID]
		if !ok {
			return errors.New("All users must be enrolled in account recovery (password reset) in order for the requests to be approved.")
		}
		key, err := v.encryptedUserKeyForDevice(orgID, r.PublicKey, d)
		if err != nil {
			return err
		}
		items = append(items, map[string]any{"id": r.ID, "approved": true, "key": key})
	}
	return v.Client.Do(ctx, http.MethodPost, "/organizations/"+orgID+"/auth-requests", items, nil)
}

func (v *Vault) DenyAuthRequest(ctx context.Context, orgID, id string) error {
	return v.Client.Do(ctx, http.MethodPost, "/organizations/"+orgID+"/auth-requests/"+id, map[string]any{"requestApproved": false}, nil)
}

func (v *Vault) DenyAuthRequests(ctx context.Context, orgID string, ids []string) error {
	return v.Client.Do(ctx, http.MethodPost, "/organizations/"+orgID+"/auth-requests/deny", map[string]any{"ids": ids}, nil)
}
