package vault

import "encoding/json"

// Encrypted server-side data as returned by /api/sync and the cipher/send endpoints.

type SyncResponse struct {
	Profile        Profile          `json:"profile"`
	Folders        []FolderData     `json:"folders"`
	Collections    []CollectionData `json:"collections"`
	Ciphers        []CipherData     `json:"ciphers"`
	Sends          []SendData       `json:"sends"`
	Policies       []PolicyData     `json:"policies"`
	Domains        *DomainsData     `json:"domains"`
	UserDecryption *UserDecryption  `json:"userDecryption"`
}

// UserDecryption carries the master-password unlock data (KDF, salt, wrapped user key).
type UserDecryption struct {
	MasterPasswordUnlock *MasterPasswordUnlock `json:"masterPasswordUnlock"`
}

type MasterPasswordUnlock struct {
	Kdf *struct {
		KdfType     int  `json:"kdfType"`
		Iterations  int  `json:"iterations"`
		Memory      *int `json:"memory"`
		Parallelism *int `json:"parallelism"`
	} `json:"kdf"`
	MasterKeyEncryptedUserKey string `json:"masterKeyEncryptedUserKey"`
	Salt                      string `json:"salt"`
}

type Profile struct {
	ID                      string                        `json:"id"`
	Name                    *string                       `json:"name"`
	Email                   string                        `json:"email"`
	Premium                 bool                          `json:"premium"`
	PremiumFromOrganization bool                          `json:"premiumFromOrganization"`
	Key                     string                        `json:"key"`
	PrivateKey              string                        `json:"privateKey"`
	AccountKeys             *AccountKeys                  `json:"accountKeys"`
	Organizations           []ProfileOrganization         `json:"organizations"`
	Providers               []ProfileProvider             `json:"providers"`
	ProviderOrganizations   []ProfileProviderOrganization `json:"providerOrganizations"`
}

type AccountKeys struct {
	PublicKeyEncryptionKeyPair *struct {
		WrappedPrivateKey string `json:"wrappedPrivateKey"`
		PublicKey         string `json:"publicKey"`
	} `json:"publicKeyEncryptionKeyPair"`
}

type OrgPermissions struct {
	EditAnyCollection   bool `json:"editAnyCollection"`
	DeleteAnyCollection bool `json:"deleteAnyCollection"`
	ManageResetPassword bool `json:"manageResetPassword"`
	ManageUsers         bool `json:"manageUsers"`
}

type ProfileOrganization struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Key                string         `json:"key"`
	Status             int            `json:"status"`
	Type               int            `json:"type"`
	Enabled            bool           `json:"enabled"`
	UsePolicies        bool           `json:"usePolicies"`
	UseTotp            bool           `json:"useTotp"`
	UsersGetPremium    bool           `json:"usersGetPremium"`
	OrganizationUserID string         `json:"organizationUserId"`
	ProviderID         *string        `json:"providerId"`
	Permissions        OrgPermissions `json:"permissions"`
}

type ProfileProvider struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Status int    `json:"status"`
}

type ProfileProviderOrganization struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Key             string         `json:"key"`
	Status          int            `json:"status"`
	Type            int            `json:"type"`
	Enabled         bool           `json:"enabled"`
	UseTotp         bool           `json:"useTotp"`
	UsersGetPremium bool           `json:"usersGetPremium"`
	ProviderID      *string        `json:"providerId"`
	Permissions     OrgPermissions `json:"permissions"`
}

type FolderData struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	RevisionDate string `json:"revisionDate"`
}

type CollectionData struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organizationId"`
	Name           string  `json:"name"`
	ExternalID     *string `json:"externalId"`
	ReadOnly       bool    `json:"readOnly"`
	HidePasswords  bool    `json:"hidePasswords"`
	Manage         bool    `json:"manage"`
}

type CipherPermissions struct {
	Delete  bool `json:"delete"`
	Restore bool `json:"restore"`
}

type CipherData struct {
	ID                  string                `json:"id"`
	OrganizationID      *string               `json:"organizationId"`
	FolderID            *string               `json:"folderId"`
	Type                int                   `json:"type"`
	Name                string                `json:"name"`
	Notes               *string               `json:"notes"`
	Favorite            bool                  `json:"favorite"`
	Edit                *bool                 `json:"edit"`
	ViewPassword        *bool                 `json:"viewPassword"`
	Permissions         *CipherPermissions    `json:"permissions"`
	OrganizationUseTotp bool                  `json:"organizationUseTotp"`
	RevisionDate        string                `json:"revisionDate"`
	CreationDate        *string               `json:"creationDate"`
	DeletedDate         *string               `json:"deletedDate"`
	ArchivedDate        *string               `json:"archivedDate"`
	Reprompt            int                   `json:"reprompt"`
	Key                 *string               `json:"key"`
	CollectionIDs       []string              `json:"collectionIds"`
	Login               *LoginData            `json:"login"`
	SecureNote          *SecureNoteData       `json:"secureNote"`
	Card                map[string]any        `json:"card"`
	Identity            map[string]any        `json:"identity"`
	SSHKey              map[string]any        `json:"sshKey"`
	BankAccount         map[string]any        `json:"bankAccount"`
	DriversLicense      map[string]any        `json:"driversLicense"`
	Passport            map[string]any        `json:"passport"`
	Fields              []FieldData           `json:"fields"`
	PasswordHistory     []PasswordHistoryData `json:"passwordHistory"`
	Attachments         []AttachmentData      `json:"attachments"`
}

func (c *CipherData) CanEdit() bool         { return c.Edit == nil || *c.Edit }
func (c *CipherData) CanViewPassword() bool { return c.ViewPassword == nil || *c.ViewPassword }

type LoginData struct {
	URIs                 []LoginURIData        `json:"uris"`
	Username             *string               `json:"username"`
	Password             *string               `json:"password"`
	PasswordRevisionDate *string               `json:"passwordRevisionDate"`
	Totp                 *string               `json:"totp"`
	AutofillOnPageLoad   *bool                 `json:"autofillOnPageLoad"`
	Fido2Credentials     []Fido2CredentialData `json:"fido2Credentials"`
}

type LoginURIData struct {
	URI         *string `json:"uri"`
	URIChecksum *string `json:"uriChecksum"`
	Match       *int    `json:"match"`
}

type Fido2CredentialData struct {
	CredentialID    *string `json:"credentialId"`
	KeyType         *string `json:"keyType"`
	KeyAlgorithm    *string `json:"keyAlgorithm"`
	KeyCurve        *string `json:"keyCurve"`
	KeyValue        *string `json:"keyValue"`
	RpID            *string `json:"rpId"`
	UserHandle      *string `json:"userHandle"`
	UserName        *string `json:"userName"`
	Counter         *string `json:"counter"`
	RpName          *string `json:"rpName"`
	UserDisplayName *string `json:"userDisplayName"`
	Discoverable    *string `json:"discoverable"`
	CreationDate    *string `json:"creationDate"`
}

type SecureNoteData struct {
	Type int `json:"type"`
}

type FieldData struct {
	Type     int     `json:"type"`
	Name     *string `json:"name"`
	Value    *string `json:"value"`
	LinkedID *int    `json:"linkedId"`
}

type PasswordHistoryData struct {
	Password     string `json:"password"`
	LastUsedDate string `json:"lastUsedDate"`
}

type AttachmentData struct {
	ID       string          `json:"id"`
	URL      *string         `json:"url"`
	FileName *string         `json:"fileName"`
	Key      *string         `json:"key"`
	Size     json.RawMessage `json:"size"`
	SizeName *string         `json:"sizeName"`
}

type SendData struct {
	ID             string        `json:"id"`
	AccessID       string        `json:"accessId"`
	Type           int           `json:"type"`
	Name           *string       `json:"name"`
	Notes          *string       `json:"notes"`
	File           *SendFileData `json:"file"`
	Text           *SendTextData `json:"text"`
	Key            string        `json:"key"`
	MaxAccessCount *int          `json:"maxAccessCount"`
	AccessCount    int           `json:"accessCount"`
	Password       *string       `json:"password"`
	Emails         *string       `json:"emails"`
	Disabled       bool          `json:"disabled"`
	RevisionDate   *string       `json:"revisionDate"`
	ExpirationDate *string       `json:"expirationDate"`
	DeletionDate   *string       `json:"deletionDate"`
	HideEmail      bool          `json:"hideEmail"`
	AuthType       *int          `json:"authType"`
}

type SendFileData struct {
	ID       *string         `json:"id"`
	FileName *string         `json:"fileName"`
	Size     json.RawMessage `json:"size"`
	SizeName *string         `json:"sizeName"`
}

type SendTextData struct {
	Text   *string `json:"text"`
	Hidden bool    `json:"hidden"`
}

type PolicyData struct {
	ID             string          `json:"id"`
	OrganizationID string          `json:"organizationId"`
	Type           int             `json:"type"`
	Data           json.RawMessage `json:"data"`
	Enabled        bool            `json:"enabled"`
}

type DomainsData struct {
	EquivalentDomains       [][]string `json:"equivalentDomains"`
	GlobalEquivalentDomains []struct {
		Type     int      `json:"type"`
		Domains  []string `json:"domains"`
		Excluded bool     `json:"excluded"`
	} `json:"globalEquivalentDomains"`
}

// Typed sub-object field lists, in CLI export order.
var (
	CardFields           = []string{"cardholderName", "brand", "number", "expMonth", "expYear", "code"}
	IdentityFields       = []string{"title", "firstName", "middleName", "lastName", "address1", "address2", "address3", "city", "state", "postalCode", "country", "company", "email", "phone", "ssn", "username", "passportNumber", "licenseNumber"}
	SSHKeyFields         = []string{"privateKey", "publicKey", "keyFingerprint"}
	BankAccountFields    = []string{"bankName", "nameOnAccount", "accountType", "accountNumber", "routingNumber", "branchNumber", "pin", "swiftCode", "iban", "bankContactPhone"}
	DriversLicenseFields = []string{"firstName", "middleName", "lastName", "dateOfBirth", "licenseNumber", "issuingCountry", "issuingState", "issueDate", "expirationDate", "issuingAuthority", "licenseClass"}
	PassportFields       = []string{"surname", "givenName", "dateOfBirth", "sex", "birthPlace", "nationality", "issuingCountry", "passportNumber", "passportType", "nationalIdentificationNumber", "issuingAuthority", "issueDate", "expirationDate"}
)

const (
	CipherTypeLogin          = 1
	CipherTypeSecureNote     = 2
	CipherTypeCard           = 3
	CipherTypeIdentity       = 4
	CipherTypeSSHKey         = 5
	CipherTypeBankAccount    = 6
	CipherTypeDriversLicense = 7
	CipherTypePassport       = 8

	FieldTypeHidden = 1

	SendTypeText = 0
	SendTypeFile = 1

	PolicyTypePasswordGenerator         = 2
	PolicyTypeOrganizationDataOwnership = 5
	PolicyTypeRestrictedItemTypes       = 15

	OrgUserTypeOwner   = 0
	OrgUserTypeAdmin   = 1
	OrgStatusConfirmed = 2
)

// typedFields returns the sub-object key and field list for typed ciphers.
func typedFields(cipherType int) (string, []string) {
	switch cipherType {
	case CipherTypeCard:
		return "card", CardFields
	case CipherTypeIdentity:
		return "identity", IdentityFields
	case CipherTypeSSHKey:
		return "sshKey", SSHKeyFields
	case CipherTypeBankAccount:
		return "bankAccount", BankAccountFields
	case CipherTypeDriversLicense:
		return "driversLicense", DriversLicenseFields
	case CipherTypePassport:
		return "passport", PassportFields
	}
	return "", nil
}

func (c *CipherData) typedData() map[string]any {
	switch c.Type {
	case CipherTypeCard:
		return c.Card
	case CipherTypeIdentity:
		return c.Identity
	case CipherTypeSSHKey:
		return c.SSHKey
	case CipherTypeBankAccount:
		return c.BankAccount
	case CipherTypeDriversLicense:
		return c.DriversLicense
	case CipherTypePassport:
		return c.Passport
	}
	return nil
}
