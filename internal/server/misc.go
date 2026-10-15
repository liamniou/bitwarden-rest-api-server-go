package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/crypto"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/generator"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/vault"
)

func itoa(i int) string { return strconv.Itoa(i) }

// --- GET /status ---

func (s *Server) status(q *request) *Response {
	st := s.v.Status()
	t := vault.NewOMap()
	if st.ServerURL != nil {
		t.Set("serverUrl", *st.ServerURL)
	} else {
		t.Set("serverUrl", nil)
	}
	t.Set("lastSync", vault.JSTime(st.LastSync))
	if st.Status != "unauthenticated" {
		t.Set("userEmail", st.UserEmail).Set("userId", st.UserID)
	}
	t.Set("status", st.Status)
	return success(templateResponse(t))
}

// --- POST /sync ---

func (s *Server) sync(q *request) *Response {
	if q.optBool("last") {
		return success(stringResponseNull(lastSyncString(s.v.LastSync())))
	}
	if err := s.v.Sync(q.r.Context(), q.optBool("force")); err != nil {
		return errResp("Syncing failed: " + err.Error())
	}
	return success(messageResponse("Syncing complete.", nil))
}

func lastSyncString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := vault.JSTime(t).(string)
	return &s
}

// --- POST /lock, POST /unlock ---

func (s *Server) lock(q *request) *Response {
	s.v.Lock()
	return success(messageResponse("Your vault is locked.", nil))
}

func (s *Server) unlock(q *request) *Response {
	var password string
	if m := q.bodyMap(); m != nil {
		password, _ = m["password"].(string)
	}
	if password == "" {
		return badRequest("Master password is required. Try again in interactive mode or provide a password file or environment variable.")
	}
	if err := s.v.Unlock(password); err != nil {
		return errFrom(err)
	}
	session := vault.NewSessionKey()
	msg := "\nTo unlock your vault, set your session key to the `BW_SESSION` environment variable. ex:\n" +
		"$ export BW_SESSION=\"" + session + "\"\n" +
		"> $env:BW_SESSION=\"" + session + "\"\n\n" +
		"You can also pass the session key to any command with the `--session` option. ex:\n" +
		"$ bw list items --session " + session
	m := messageResponse("Your vault is now unlocked!", &msg)
	m.Set("raw", session)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := s.v.Sync(ctx, false); err != nil {
			s.log.Debug("post-unlock sync failed", "err", err)
		}
	}()
	return success(m)
}

// --- GET /generate ---

func (s *Server) generate(q *request) *Response {
	o := generator.Options{
		Uppercase:     q.optBool("uppercase"),
		Lowercase:     q.optBool("lowercase"),
		Number:        q.optBool("number"),
		Special:       q.optBool("special"),
		Capitalize:    q.optBool("capitalize"),
		IncludeNumber: q.optBool("includeNumber"),
		Ambiguous:     !q.optBool("ambiguous"),
		Length:        q.optInt(14, "length"),
		NumWords:      q.optInt(6, "words"),
		MinNumber:     q.optInt(1, "minNumber"),
		MinSpecial:    q.optInt(0, "minSpecial"),
		WordSeparator: "-",
		Type:          "password",
	}
	if q.optBool("passphrase") {
		o.Type = "passphrase"
	}
	if sep := q.opt("separator"); sep != nil {
		o.WordSeparator = *sep
	}
	if !o.Uppercase && !o.Lowercase && !o.Special && !o.Number {
		o.Lowercase, o.Uppercase, o.Number = true, true, true
	}
	if o.Length < 5 {
		o.Length = 5
	}
	if o.NumWords < 3 {
		o.NumWords = 3
	}
	switch o.WordSeparator {
	case "space":
		o.WordSeparator = " "
	case "empty":
		o.WordSeparator = ""
	default:
		if r := []rune(o.WordSeparator); len(r) > 1 {
			o.WordSeparator = string(r[0])
		}
	}
	var policy *generator.Policy
	if s.v.CheckUnlocked() == nil {
		policy = s.generatorPolicy()
	}
	o = generator.Enforce(o, policy)
	return success(stringResponse(generator.Generate(o)))
}

func (s *Server) generatorPolicy() *generator.Policy {
	p := &generator.Policy{}
	for _, pol := range s.v.Policies(vault.PolicyTypePasswordGenerator, false) {
		var d map[string]any
		if json.Unmarshal(pol.Data, &d) != nil {
			continue
		}
		num := func(k string) int {
			if f, ok := d[k].(float64); ok {
				return int(f)
			}
			return 0
		}
		b := func(k string) bool { v, _ := d[k].(bool); return v }
		if t, _ := d["overridePasswordType"].(string); t != "" && p.OverridePasswordType != "password" {
			// "password" wins over "passphrase" when organizations disagree.
			p.OverridePasswordType = t
		}
		p.MinLength = max(p.MinLength, num("minLength"))
		p.UseUppercase = p.UseUppercase || b("useUpper")
		p.UseLowercase = p.UseLowercase || b("useLower")
		p.UseNumbers = p.UseNumbers || b("useNumbers")
		p.NumberCount = max(p.NumberCount, num("minNumbers"))
		p.UseSpecial = p.UseSpecial || b("useSpecial")
		p.SpecialCount = max(p.SpecialCount, num("minSpecial"))
		p.MinNumberWords = max(p.MinNumberWords, num("minNumberWords"))
		p.Capitalize = p.Capitalize || b("capitalize")
		p.IncludeNumber = p.IncludeNumber || b("includeNumber")
	}
	return p
}

// --- POST /confirm/{object}/{id} ---

func (s *Server) confirm(q *request) *Response {
	if strings.ToLower(q.r.PathValue("object")) != "org-member" {
		return badRequest("Unknown object.")
	}
	id := strings.ToLower(q.r.PathValue("id"))
	orgID := q.optStr("organizationid", "organizationId")
	if orgID == "" {
		return badRequest("--organizationid <organizationid> required.")
	}
	if !isGUID(id) {
		return badRequest("`" + id + "` is not a GUID.")
	}
	if !isGUID(orgID) {
		return badRequest("`" + orgID + "` is not a GUID.")
	}
	ctx := q.r.Context()
	orgKey := s.v.OrgKey(orgID)
	if orgKey == nil {
		return errResp("No encryption key for this organization.")
	}
	u, err := s.v.GetOrgUser(ctx, orgID, id)
	if err != nil {
		return errFrom(err)
	}
	if u == nil || u.ID == "" {
		return errResp("Member id does not exist for this organization.")
	}
	switch u.Status {
	case 0:
		return errResp("User must accept the invitation before they can be confirmed.")
	case 2:
		return errResp("User is already confirmed.")
	case -1:
		return errResp("User is revoked and cannot be confirmed.")
	case 1:
	default:
		return errResp("User is not in a valid state to be confirmed.")
	}
	if u.UserID == nil {
		return errResp("User is not in a valid state to be confirmed.")
	}
	pub, err := s.v.UserPublicKey(ctx, *u.UserID)
	if err != nil {
		return errFrom(err)
	}
	key, err := crypto.EncapsulateKey(orgKey, pub)
	if err != nil {
		return errFrom(err)
	}
	collName, err := crypto.EncryptString(orgKey, "My Items")
	if err != nil {
		return errFrom(err)
	}
	if err := s.v.ConfirmOrgUser(ctx, orgID, id, map[string]any{"key": key, "defaultUserCollectionName": collName}); err != nil {
		return errFrom(err)
	}
	return success(nil)
}

// --- device approval (Bitwarden-licensed endpoints) ---

const noApprovePermission = "You do not have permission to approve pending device authorization requests."

func (s *Server) deviceApprovalOrg(q *request) (string, *Response) {
	orgID := strings.ToLower(q.r.PathValue("organizationId"))
	if !isGUID(orgID) {
		return "", badRequest("`" + orgID + "` is not a GUID.")
	}
	org := s.v.Organization(orgID)
	if org == nil || !org.CanManageUsersPassword() {
		return "", errResp(noApprovePermission)
	}
	return orgID, nil
}

func (s *Server) deviceApprovalList(q *request) *Response {
	orgID, r := s.deviceApprovalOrg(q)
	if r != nil {
		return r
	}
	reqs, err := s.v.ListPendingAuthRequests(q.r.Context(), orgID)
	if err != nil {
		return errFrom(err)
	}
	items := make([]any, 0, len(reqs))
	for _, ar := range reqs {
		fp := ""
		if pub, err := decodeB64(ar.PublicKey); err == nil {
			fp = fingerprint(ar.Email, pub)
		}
		created := vault.ParseTime(&ar.CreationDate)
		items = append(items, vault.NewOMap().Set("object", "auth-request").Set("id", ar.ID).
			Set("userId", ar.UserID).Set("organizationUserId", ar.OrganizationUserID).Set("email", ar.Email).
			Set("requestDeviceIdentifier", ar.RequestDeviceIdentifier).Set("requestDeviceType", ar.RequestDeviceType).
			Set("requestIpAddress", ar.RequestIPAddress).Set("creationDate", vault.JSTime(created)).
			Set("fingerprintPhrase", fp))
	}
	return success(listResponse(items))
}

func (s *Server) deviceApprovalApprove(q *request) *Response {
	orgID, r := s.deviceApprovalOrg(q)
	if r != nil {
		return r
	}
	id := strings.ToLower(q.r.PathValue("requestId"))
	if !isGUID(id) {
		return badRequest("`" + id + "` is not a GUID.")
	}
	reqs, err := s.v.ListPendingAuthRequests(q.r.Context(), orgID)
	if err != nil {
		return errFrom(err)
	}
	for _, ar := range reqs {
		if ar.ID == id {
			if err := s.v.ApproveAuthRequest(q.r.Context(), orgID, ar); err != nil {
				return errFrom(err)
			}
			return success(nil)
		}
	}
	return errResp("The request id is invalid.")
}

func (s *Server) deviceApprovalApproveAll(q *request) *Response {
	orgID, r := s.deviceApprovalOrg(q)
	if r != nil {
		return r
	}
	reqs, err := s.v.ListPendingAuthRequests(q.r.Context(), orgID)
	if err != nil {
		return errFrom(err)
	}
	if len(reqs) == 0 {
		return success(messageResponse("No pending device authorization requests to approve.", nil))
	}
	if err := s.v.ApproveAuthRequests(q.r.Context(), orgID, reqs); err != nil {
		return errFrom(err)
	}
	return success(nil)
}

func (s *Server) deviceApprovalDeny(q *request) *Response {
	orgID, r := s.deviceApprovalOrg(q)
	if r != nil {
		return r
	}
	id := strings.ToLower(q.r.PathValue("requestId"))
	if !isGUID(id) {
		return badRequest("`" + id + "` is not a GUID.")
	}
	reqs, err := s.v.ListPendingAuthRequests(q.r.Context(), orgID)
	if err != nil {
		return errFrom(err)
	}
	for _, ar := range reqs {
		if ar.ID == id {
			if err := s.v.DenyAuthRequest(q.r.Context(), orgID, id); err != nil {
				return errFrom(err)
			}
			return success(nil)
		}
	}
	return errResp("The request id is invalid.")
}

func (s *Server) deviceApprovalDenyAll(q *request) *Response {
	orgID, r := s.deviceApprovalOrg(q)
	if r != nil {
		return r
	}
	reqs, err := s.v.ListPendingAuthRequests(q.r.Context(), orgID)
	if err != nil {
		return errFrom(err)
	}
	if len(reqs) == 0 {
		return success(messageResponse("No pending device authorization requests to deny.", nil))
	}
	ids := make([]string, 0, len(reqs))
	for _, ar := range reqs {
		ids = append(ids, ar.ID)
	}
	if err := s.v.DenyAuthRequests(q.r.Context(), orgID, ids); err != nil {
		return errFrom(err)
	}
	return success(nil)
}
