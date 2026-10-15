// Package api is a minimal Bitwarden server API client.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	ClientName    = "cli"
	ClientVersion = "2026.9.1"
	DeviceType    = "25" // LinuxCLI
	DeviceName    = "linux"
)

// URLs holds the resolved service endpoints.
type URLs struct {
	Base     string // empty for the default bitwarden.com cloud
	API      string
	Identity string
	WebVault string
	Send     string // empty unless a dedicated send domain is configured
}

// ResolveURLs replicates `bw config server <url>` environment resolution.
func ResolveURLs(base, apiOverride, identityOverride string) URLs {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	var u URLs
	if base == "" || base == "bitwarden.com" || base == "https://bitwarden.com" {
		u = URLs{
			API:      "https://api.bitwarden.com",
			Identity: "https://identity.bitwarden.com",
			WebVault: "https://vault.bitwarden.com",
			Send:     "https://send.bitwarden.com",
		}
	} else {
		u = URLs{Base: base, API: base + "/api", Identity: base + "/identity", WebVault: base}
	}
	if apiOverride != "" {
		u.API = strings.TrimRight(apiOverride, "/")
	}
	if identityOverride != "" {
		u.Identity = strings.TrimRight(identityOverride, "/")
	}
	return u
}

// SendURL mirrors Environment.getSendUrl().
func (u URLs) SendURL() string {
	if u.Send != "" {
		if u.Send == "https://send.bitwarden.com" {
			return u.Send + "/#"
		}
		if strings.HasSuffix(u.Send, "/#/send/") {
			return u.Send
		}
		return u.Send + "/#/send/"
	}
	return u.WebVault + "/#/send/"
}

// Credentials used to obtain access tokens.
type Credentials struct {
	ClientID     string
	ClientSecret string
	Email        string
	PasswordHash string
}

// Error carries the server's error message, mimicking ErrorResponse.getSingleMessage().
type Error struct {
	StatusCode int
	Message    string
}

func (e *Error) Error() string { return e.Message }

func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.StatusCode == http.StatusNotFound
}

// Client is safe for concurrent use.
type Client struct {
	URLs     URLs
	DeviceID string
	HTTP     *http.Client

	mu           sync.Mutex
	creds        Credentials
	accessToken  string
	refreshToken string
	expiresAt    time.Time
}

func NewClient(urls URLs, deviceID string) *Client {
	return &Client{
		URLs:     urls,
		DeviceID: deviceID,
		HTTP:     &http.Client{Timeout: 5 * time.Minute},
	}
}

// TokenResponse is the identity /connect/token payload (PascalCase extensions).
type TokenResponse struct {
	AccessToken           string          `json:"access_token"`
	ExpiresIn             int             `json:"expires_in"`
	RefreshToken          string          `json:"refresh_token"`
	TokenType             string          `json:"token_type"`
	Key                   string          `json:"Key"`
	PrivateKey            string          `json:"PrivateKey"`
	Kdf                   *int            `json:"Kdf"`
	KdfIterations         *int            `json:"KdfIterations"`
	KdfMemory             *int            `json:"KdfMemory"`
	KdfParallelism        *int            `json:"KdfParallelism"`
	AccountKeys           json.RawMessage `json:"AccountKeys"`
	UserDecryptionOptions json.RawMessage `json:"UserDecryptionOptions"`
	ApiUseKeyConnector    bool            `json:"ApiUseKeyConnector"`
	TwoFactorProviders    json.RawMessage `json:"TwoFactorProviders2"`
}

func (c *Client) commonHeaders(h http.Header) {
	h.Set("Device-Type", DeviceType)
	h.Set("Bitwarden-Client-Name", ClientName)
	h.Set("Bitwarden-Client-Version", ClientVersion)
	h.Set("User-Agent", "Bitwarden_CLI/"+ClientVersion+" (go)")
}

// LoginAPIKey performs the client_credentials grant used by `bw login --apikey`.
func (c *Client) LoginAPIKey(ctx context.Context, clientID, clientSecret string) (*TokenResponse, error) {
	scope := "api"
	if strings.HasPrefix(clientID, "organization") {
		scope = "api.organization"
	}
	form := url.Values{
		"grant_type":       {"client_credentials"},
		"scope":            {scope},
		"client_id":        {clientID},
		"client_secret":    {clientSecret},
		"deviceType":       {DeviceType},
		"deviceIdentifier": {c.DeviceID},
		"deviceName":       {DeviceName},
	}
	tr, err := c.postToken(ctx, form, nil)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.creds = Credentials{ClientID: clientID, ClientSecret: clientSecret}
	c.setTokenLocked(tr)
	c.mu.Unlock()
	return tr, nil
}

// PreloginResponse contains the KDF configuration for an email.
type PreloginResponse struct {
	Kdf            int    `json:"kdf"`
	KdfIterations  int    `json:"kdfIterations"`
	KdfMemory      *int   `json:"kdfMemory"`
	KdfParallelism *int   `json:"kdfParallelism"`
	Salt           string `json:"salt"`
}

func (c *Client) Prelogin(ctx context.Context, email string) (*PreloginResponse, error) {
	var out PreloginResponse
	body := map[string]string{"email": email}
	err := c.doJSON(ctx, http.MethodPost, c.URLs.Identity+"/accounts/prelogin/password", body, &out, false)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && e.StatusCode == http.StatusNotFound {
			err = c.doJSON(ctx, http.MethodPost, c.URLs.Identity+"/accounts/prelogin", body, &out, false)
		}
	}
	return &out, err
}

// LoginPassword performs the password grant (no interactive 2FA support).
func (c *Client) LoginPassword(ctx context.Context, email, passwordHash, twoFactorToken, twoFactorProvider string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":       {"password"},
		"scope":            {"api offline_access"},
		"client_id":        {ClientName},
		"username":         {email},
		"password":         {passwordHash},
		"deviceType":       {DeviceType},
		"deviceIdentifier": {c.DeviceID},
		"deviceName":       {DeviceName},
	}
	if twoFactorToken != "" {
		form.Set("twoFactorToken", twoFactorToken)
		form.Set("twoFactorProvider", twoFactorProvider)
		form.Set("twoFactorRemember", "0")
	}
	hdr := http.Header{}
	hdr.Set("Auth-Email", base64.RawURLEncoding.EncodeToString([]byte(email)))
	tr, err := c.postToken(ctx, form, hdr)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.creds = Credentials{Email: email, PasswordHash: passwordHash}
	c.setTokenLocked(tr)
	c.mu.Unlock()
	return tr, nil
}

func (c *Client) setTokenLocked(tr *TokenResponse) {
	c.accessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		c.refreshToken = tr.RefreshToken
	}
	exp := tr.ExpiresIn
	if exp <= 0 {
		exp = 3600
	}
	c.expiresAt = time.Now().Add(time.Duration(exp) * time.Second)
}

// Logout forgets the current tokens.
func (c *Client) Logout() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken, c.refreshToken = "", ""
	c.creds = Credentials{}
}

func (c *Client) HasAccessToken() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accessToken != ""
}

// AccessToken returns a valid bearer token, refreshing it when it is close to expiry.
func (c *Client) AccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessToken == "" {
		return "", errors.New("You are not logged in.")
	}
	if time.Until(c.expiresAt) > 5*time.Minute {
		return c.accessToken, nil
	}
	var form url.Values
	switch {
	case c.creds.ClientID != "" && c.creds.ClientSecret != "":
		scope := "api"
		if strings.HasPrefix(c.creds.ClientID, "organization") {
			scope = "api.organization"
		}
		form = url.Values{
			"grant_type": {"client_credentials"}, "scope": {scope},
			"client_id": {c.creds.ClientID}, "client_secret": {c.creds.ClientSecret},
			"deviceType": {DeviceType}, "deviceIdentifier": {c.DeviceID}, "deviceName": {DeviceName},
		}
	case c.refreshToken != "":
		form = url.Values{
			"grant_type": {"refresh_token"}, "client_id": {ClientName}, "refresh_token": {c.refreshToken},
		}
	default:
		return c.accessToken, nil
	}
	tr, err := c.postToken(ctx, form, nil)
	if err != nil {
		return "", err
	}
	c.setTokenLocked(tr)
	return c.accessToken, nil
}

func (c *Client) postToken(ctx context.Context, form url.Values, extra http.Header) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URLs.Identity+"/connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	c.commonHeaders(req.Header)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	for k, v := range extra {
		req.Header[k] = v
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, parseIdentityError(resp.StatusCode, raw)
	}
	var tr TokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, fmt.Errorf("invalid identity response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, errors.New("Identity response does not contain a valid access token")
	}
	return &tr, nil
}

func parseIdentityError(status int, raw []byte) error {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if _, ok := m["TwoFactorProviders2"]; ok {
		return &Error{StatusCode: status, Message: "Two-step login is required. Use API key authentication (BW_CLIENTID/BW_CLIENTSECRET) or set BW_TWO_FACTOR_TOKEN and BW_TWO_FACTOR_METHOD."}
	}
	if em, ok := m["ErrorModel"].(map[string]any); ok {
		if msg, ok := em["Message"].(string); ok && msg != "" {
			return &Error{StatusCode: status, Message: msg}
		}
	}
	if d, ok := m["error_description"].(string); ok && d != "" {
		return &Error{StatusCode: status, Message: d}
	}
	if e, ok := m["error"].(string); ok && e != "" {
		return &Error{StatusCode: status, Message: e}
	}
	return &Error{StatusCode: status, Message: fmt.Sprintf("identity server returned HTTP %d", status)}
}

// parseAPIError mirrors ErrorResponse + getErrorMessage in the CLI.
func parseAPIError(status int, contentType string, raw []byte) error {
	if status == http.StatusTooManyRequests {
		return &Error{StatusCode: status, Message: "Rate limit exceeded. Try again later."}
	}
	trimmed := bytes.TrimSpace(raw)
	if strings.Contains(contentType, "application/json") && len(trimmed) > 0 {
		var m map[string]any
		if json.Unmarshal(trimmed, &m) == nil {
			norm := map[string]any{}
			for k, v := range m {
				norm[strings.ToLower(k)] = v
			}
			if ve, ok := norm["validationerrors"].(map[string]any); ok {
				for _, v := range ve {
					if arr, ok := v.([]any); ok && len(arr) > 0 {
						if s, ok := arr[0].(string); ok {
							return &Error{StatusCode: status, Message: s}
						}
					}
				}
			}
			if msg, ok := norm["message"].(string); ok && msg != "" {
				return &Error{StatusCode: status, Message: msg}
			}
		}
		var compact bytes.Buffer
		if json.Compact(&compact, trimmed) == nil {
			return &Error{StatusCode: status, Message: fmt.Sprintf(`{"response":%s,"statusCode":%d}`, compact.String(), status)}
		}
	}
	if strings.Contains(contentType, "text/plain") && len(trimmed) > 0 {
		return &Error{StatusCode: status, Message: string(trimmed)}
	}
	return &Error{StatusCode: status, Message: fmt.Sprintf(`{"response":null,"statusCode":%d}`, status)}
}

// Do sends an authenticated JSON request to the API service.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	return c.doJSON(ctx, method, c.URLs.API+path, body, out, true)
}

func (c *Client) doJSON(ctx context.Context, method, fullURL string, body, out any, authed bool) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	return c.send(ctx, req, out, authed)
}

// DoMultipart posts a single file part named "data" (attachment/send direct upload).
func (c *Client) DoMultipart(ctx context.Context, path, fileName string, data []byte) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name="data"; filename="%s"`, strings.ReplaceAll(fileName, `"`, `\"`))}
	h["Content-Type"] = []string{"application/octet-stream"}
	part, err := w.CreatePart(h)
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URLs.API+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	return c.send(ctx, req, nil, true)
}

func (c *Client) send(ctx context.Context, req *http.Request, out any, authed bool) error {
	c.commonHeaders(req.Header)
	req.Header.Set("Accept", "application/json")
	if req.Method == http.MethodGet {
		req.Header.Set("Cache-Control", "no-store")
		req.Header.Set("Pragma", "no-cache")
	}
	if authed {
		tok, err := c.AccessToken(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	// A revoked token (e.g. security stamp change) is refreshed once and retried.
	if authed && resp.StatusCode == http.StatusUnauthorized && (req.Body == nil || req.GetBody != nil) {
		resp.Body.Close()
		c.expireToken()
		tok, err := c.AccessToken(ctx)
		if err != nil {
			return err
		}
		retry := req.Clone(ctx)
		if req.GetBody != nil {
			if retry.Body, err = req.GetBody(); err != nil {
				return err
			}
		}
		retry.Header.Set("Authorization", "Bearer "+tok)
		if resp, err = c.HTTP.Do(retry); err != nil {
			return err
		}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseAPIError(resp.StatusCode, resp.Header.Get("Content-Type"), raw)
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decoding %s %s response: %w", req.Method, req.URL.Path, err)
		}
	}
	return nil
}

// Download fetches an absolute URL without Bitwarden auth (attachment blobs).
func (c *Client) Download(ctx context.Context, rawURL string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	b, err := io.ReadAll(resp.Body)
	return b, resp.StatusCode, err
}

// UploadAzure uploads an encrypted blob to an Azure SAS URL as a single block blob.
func (c *Client) UploadAzure(ctx context.Context, sasURL string, data []byte) error {
	u, err := url.Parse(sasURL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, sasURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	req.Header.Set("x-ms-version", u.Query().Get("sv"))
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	req.ContentLength = int64(len(data))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("azure upload failed: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// JWTClaims decodes the (unverified) access token payload.
func JWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

func (c *Client) expireToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expiresAt = time.Time{}
}

// CurrentAccessToken returns the raw token without refreshing.
func (c *Client) CurrentAccessToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accessToken
}
