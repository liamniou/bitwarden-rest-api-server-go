package server

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/crypto"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/vault"
)

func jsonUnmarshal(raw []byte, v any) error {
	if len(raw) == 0 {
		return io.EOF
	}
	return json.Unmarshal(raw, v)
}

func newItemTypesEnabled(t int) bool {
	return t != vault.CipherTypeBankAccount && t != vault.CipherTypeDriversLicense && t != vault.CipherTypePassport
}

// --- POST /object/{object} ---

func (s *Server) create(q *request) *Response {
	object := q.r.PathValue("object")
	if object == "send" {
		return s.sendCreate(q)
	}
	switch strings.ToLower(object) {
	case "item":
		req := q.bodyMap()
		if req == nil {
			return badRequest("Error parsing the encoded request data.")
		}
		view, err := vault.ApplyCipherExport(req, nil)
		if err != nil {
			return errFrom(err)
		}
		if !newItemTypesEnabled(view.Type) {
			return errResp("Item type " + itoa(view.Type) + " is not available.")
		}
		if isRestricted(view, s.restrictions()) {
			return errResp("Creating this item type is restricted by organizational policy.")
		}
		c, err := s.v.CreateCipher(q.r.Context(), view)
		if err != nil {
			return errFrom(err)
		}
		return success(c.ToCLI())
	case "folder":
		req := q.bodyMap()
		if req == nil {
			return badRequest("Error parsing the encoded request data.")
		}
		name, _ := req["name"].(string)
		f, err := s.v.SaveFolder(q.r.Context(), "", name)
		if err != nil {
			return errFrom(err)
		}
		return success(f.ToCLI())
	case "org-collection":
		return s.saveOrgCollection(q, "")
	}
	return badRequest("Unknown object.")
}

func (s *Server) saveOrgCollection(q *request, id string) *Response {
	req := q.bodyMap()
	if req == nil {
		return badRequest("Error parsing the encoded request data.")
	}
	if id != "" && !isGUID(id) {
		return badRequest("`" + id + "` is not a GUID.")
	}
	optOrg := q.opt("organizationid", "organizationId")
	reqOrg, _ := req["organizationId"].(string)
	orgID := reqOrg
	if !isNullOrWhitespace(optOrg) {
		orgID = *optOrg
	}
	if strings.TrimSpace(orgID) == "" {
		return badRequest("An organization id is required, either via the `--organizationid` option " +
			"(or `organizationId` query parameter when using `bw serve`), " +
			"or the request's `organizationId` property.")
	}
	if !isGUID(orgID) {
		return badRequest("`" + orgID + "` is not a GUID.")
	}
	if !isNullOrWhitespace(optOrg) && strings.TrimSpace(reqOrg) != "" && *optOrg != reqOrg {
		return badRequest("The `--organizationid` option (or `organizationId` query parameter) does not match " +
			"the request's `organizationId` property.")
	}
	name, _ := req["name"].(string)
	if strings.TrimSpace(name) == "" {
		return badRequest("Collection name is required.")
	}
	orgKey := s.v.OrgKey(orgID)
	if orgKey == nil {
		return errResp("No encryption key for this organization.")
	}
	sel := func(key string) []map[string]any {
		raw, ok := req[key].([]any)
		if !ok {
			return nil
		}
		out := make([]map[string]any, 0, len(raw))
		for _, r := range raw {
			m, _ := r.(map[string]any)
			if m == nil {
				continue
			}
			out = append(out, map[string]any{"id": m["id"], "readOnly": m["readOnly"] == true,
				"hidePasswords": m["hidePasswords"] == true, "manage": m["manage"] == true})
		}
		return out
	}
	groups, users := sel("groups"), sel("users")
	if id == "" && users == nil {
		org := s.v.Organization(orgID)
		if org == nil {
			return errResp("Organization not found.")
		}
		users = []map[string]any{{"id": org.OrganizationUserID, "readOnly": false, "hidePasswords": false, "manage": true}}
	}
	if groups == nil {
		groups = []map[string]any{}
	}
	if users == nil {
		users = []map[string]any{}
	}
	encName, err := crypto.EncryptString(orgKey, name)
	if err != nil {
		return errFrom(err)
	}
	body := map[string]any{"name": encName, "groups": groups, "users": users}
	if ext, ok := req["externalId"].(string); ok {
		body["externalId"] = ext
	}
	resp, err := s.v.SaveOrgCollection(q.r.Context(), orgID, id, body)
	if err != nil {
		return errFrom(err)
	}
	var ext *string
	if e, ok := req["externalId"].(string); ok {
		ext = &e
	}
	return success(orgCollectionCLI(resp.ID, orgID, name, ext, resp.Groups, resp.Users))
}

// --- PUT /object/{object}/{id} ---

func (s *Server) edit(q *request) *Response {
	object := q.r.PathValue("object")
	id := strings.ToLower(q.r.PathValue("id"))
	if object == "send" {
		return s.sendEdit(q, q.r.PathValue("id"))
	}
	switch strings.ToLower(object) {
	case "item":
		req := q.bodyMap()
		if req == nil {
			return badRequest("Error parsing the encoded request data.")
		}
		return s.editCipher(q, id, req)
	case "item-collections":
		ids, ok := q.body.([]any)
		if !ok {
			return badRequest("Error parsing the encoded request data.")
		}
		d := s.v.CipherData(id)
		if d == nil {
			return notFound()
		}
		if d.OrganizationID == nil {
			return badRequest("Item does not belong to an organization. Consider moving it first.")
		}
		if !d.CanViewPassword() {
			return errResp("You do not have permission to edit this item")
		}
		strIDs := make([]string, 0, len(ids))
		for _, x := range ids {
			if s, ok := x.(string); ok {
				strIDs = append(strIDs, s)
			}
		}
		c, err := s.v.SaveCipherCollections(q.r.Context(), id, strIDs)
		if err != nil {
			return errFrom(err)
		}
		if c == nil {
			return success(nil)
		}
		return success(c.ToCLI())
	case "folder":
		req := q.bodyMap()
		if req == nil {
			return badRequest("Error parsing the encoded request data.")
		}
		f := s.v.Folder(id)
		if f == nil {
			return notFound()
		}
		name, _ := req["name"].(string)
		nf, err := s.v.SaveFolder(q.r.Context(), id, name)
		if err != nil {
			return errFrom(err)
		}
		return success(nf.ToCLI())
	case "org-collection":
		return s.saveOrgCollection(q, id)
	}
	return badRequest("Unknown object.")
}

func (s *Server) editCipher(q *request, id string, req map[string]any) *Response {
	existing := s.v.Cipher(id)
	if existing == nil {
		return notFound()
	}
	if existing.OrganizationID != nil && !existing.Edit {
		org := s.v.Organization(*existing.OrganizationID)
		if org == nil || !org.CanEditAllCiphers() {
			return errResp("You do not have permission to edit this item")
		}
	}
	if existing.IsDeleted() {
		return badRequest("You may not edit a deleted item. Use the restore command first.")
	}
	origPassword, origTotp := (*string)(nil), (*string)(nil)
	if existing.Login != nil {
		origPassword, origTotp = existing.Login.Password, existing.Login.Totp
	}
	hidden := map[string][]*string{}
	for _, f := range existing.Fields {
		if f.Type == vault.FieldTypeHidden {
			k := derefStr(f.Name)
			hidden[k] = append(hidden[k], f.Value)
		}
	}
	view, err := vault.ApplyCipherExport(req, vault.CloneCipherView(existing))
	if err != nil {
		return errFrom(err)
	}
	if !existing.ViewPassword {
		if view.Login != nil {
			if view.Login.Password == nil {
				view.Login.Password = origPassword
			}
			if view.Login.Totp == nil {
				view.Login.Totp = origTotp
			}
		}
		for i := range view.Fields {
			f := &view.Fields[i]
			if f.Type != vault.FieldTypeHidden || f.Value != nil {
				continue
			}
			if vals := hidden[derefStr(f.Name)]; len(vals) > 0 {
				f.Value = vals[0]
				hidden[derefStr(f.Name)] = vals[1:]
			}
		}
	}
	if view.IsArchived() && !s.v.HasPremium() {
		s.log.Info("Archive is only available with a Premium subscription, which has ended. Your edit was saved and the item was moved back to your vault.")
		view.ArchivedDate = nil
	}
	if isRestricted(view, s.restrictions()) {
		return errResp("Editing this item type is restricted by organizational policy.")
	}
	if view.OrganizationID == nil && len(s.v.Policies(vault.PolicyTypeOrganizationDataOwnership, true)) > 0 {
		return errResp("An organization policy restricts editing this cipher. Please use the share command first before modifying it.")
	}
	c, err := s.v.UpdateCipher(q.r.Context(), view)
	if err != nil {
		return errFrom(err)
	}
	return success(c.ToCLI())
}

// --- DELETE /object/{object}/{id} ---

func (s *Server) delete(q *request) *Response {
	object := q.r.PathValue("object")
	id := strings.ToLower(q.r.PathValue("id"))
	if object == "send" {
		return s.sendDelete(q, q.r.PathValue("id"))
	}
	ctx := q.r.Context()
	switch strings.ToLower(object) {
	case "item":
		c := s.v.Cipher(id)
		if c == nil {
			return notFound()
		}
		if c.OrganizationID != nil {
			allowed := c.Permissions == nil || c.Permissions.Delete
			if org := s.v.Organization(*c.OrganizationID); org != nil && org.CanEditAllCiphers() {
				allowed = true
			}
			if !allowed {
				return errResp("You do not have permission to delete this item.")
			}
		}
		if isRestricted(c, s.restrictions()) {
			return errResp("Deleting this item type is restricted by organizational policy.")
		}
		if err := s.v.DeleteCipher(ctx, id, q.optBool("permanent")); err != nil {
			return errFrom(err)
		}
		return success(nil)
	case "attachment":
		itemID := strings.ToLower(q.optStr("itemid", "itemId"))
		if itemID == "" {
			return badRequest("`itemid` option is required.")
		}
		c := s.v.Cipher(itemID)
		if c == nil {
			return notFound()
		}
		if len(c.Attachments) == 0 {
			return errResp("No attachments available for this item.")
		}
		var att *vault.AttachmentView
		for i := range c.Attachments {
			if strings.ToLower(c.Attachments[i].ID) == id {
				att = &c.Attachments[i]
				break
			}
		}
		if att == nil {
			return errResp("Attachment `" + id + "` was not found.")
		}
		if c.OrganizationID == nil && !s.v.HasPremium() {
			return errResp("Premium status is required to use this feature.")
		}
		if err := s.v.DeleteAttachment(ctx, c.ID, att.ID); err != nil {
			return errFrom(err)
		}
		return success(nil)
	case "folder":
		if s.v.Folder(id) == nil {
			return notFound()
		}
		if err := s.v.DeleteFolder(ctx, id); err != nil {
			return errFrom(err)
		}
		return success(nil)
	case "org-collection":
		orgID := q.optStr("organizationid", "organizationId")
		if orgID == "" {
			return badRequest("`organizationid` options is required.")
		}
		if !isGUID(id) {
			return badRequest("`" + id + "` is not a GUID.")
		}
		if !isGUID(orgID) {
			return badRequest("`" + orgID + "` is not a GUID.")
		}
		if err := s.v.DeleteOrgCollection(ctx, orgID, id); err != nil {
			return errFrom(err)
		}
		return success(nil)
	}
	return badRequest("Unknown object.")
}

// --- POST /restore/{object}/{id} ---

func (s *Server) restore(q *request) *Response {
	if strings.ToLower(q.r.PathValue("object")) != "item" {
		return badRequest("Unknown object.")
	}
	id := strings.ToLower(q.r.PathValue("id"))
	c := s.v.Cipher(id)
	if c == nil {
		return notFound()
	}
	if c.ArchivedDate != nil && c.DeletedDate == nil {
		if err := s.v.ArchiveCipher(q.r.Context(), id, false); err != nil {
			return errFrom(err)
		}
		return success(nil)
	}
	if c.DeletedDate == nil {
		return badRequest("Cipher is not in trash.")
	}
	if c.OrganizationID != nil {
		allowed := c.Permissions == nil || c.Permissions.Restore
		if org := s.v.Organization(*c.OrganizationID); org != nil && org.CanEditAllCiphers() {
			allowed = true
		}
		if !allowed {
			return errResp("You do not have permission to restore this item")
		}
	}
	if err := s.v.RestoreCipher(q.r.Context(), id); err != nil {
		return errFrom(err)
	}
	return success(nil)
}

// --- POST /archive/{object}/{id} ---

func (s *Server) archive(q *request) *Response {
	if strings.ToLower(q.r.PathValue("object")) != "item" {
		return badRequest("Unknown object.")
	}
	id := strings.ToLower(q.r.PathValue("id"))
	c := s.v.Cipher(id)
	if c == nil {
		return notFound()
	}
	switch {
	case !s.v.HasPremium():
		return errResp("Premium status is required to use this feature.")
	case c.IsArchived():
		return errResp("Item is already archived.")
	case c.IsDeleted():
		return errResp("Item is in the trash, the item must be restored before archiving.")
	}
	if err := s.v.ArchiveCipher(q.r.Context(), id, true); err != nil {
		return errFrom(err)
	}
	return success(nil)
}

// --- POST /move/{id}/{organizationId} ---

func (s *Server) move(q *request) *Response {
	raw, ok := q.body.([]any)
	if !ok {
		return badRequest("Error parsing the encoded request data.")
	}
	collectionIDs := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok {
			collectionIDs = append(collectionIDs, s)
		}
	}
	id := strings.ToLower(q.r.PathValue("id"))
	orgID := strings.ToLower(q.r.PathValue("organizationId"))
	c := s.v.Cipher(id)
	if c == nil {
		return notFound()
	}
	if c.OrganizationID != nil {
		return badRequest("This item already belongs to an organization.")
	}
	org := s.v.Organization(orgID)
	if org == nil {
		return badRequest("Organization not found.")
	}
	cols := map[string]*vault.CollectionView{}
	for _, col := range s.v.Collections() {
		if col.OrganizationID == orgID {
			cols[col.ID] = col
		}
	}
	for _, cid := range collectionIDs {
		col := cols[cid]
		if col == nil || !(org.CanEditAllCiphers() || col.Manage || !col.ReadOnly) {
			return badRequest("You do not have permission to add items to this collection.")
		}
	}
	nc, err := s.v.ShareCipher(q.r.Context(), id, orgID, collectionIDs)
	if err != nil {
		return errFrom(err)
	}
	return success(nc.ToCLI())
}

// --- POST /attachment (multipart, field "file") ---

func (s *Server) createAttachment(q *request) *Response {
	itemID := strings.ToLower(q.optStr("itemid", "itemId"))
	if itemID == "" {
		return badRequest("`itemid` option is required.")
	}
	if err := q.r.ParseMultipartForm(32 << 20); err != nil {
		return badRequest("File not provided.")
	}
	file, hdr, err := q.r.FormFile("file")
	if err != nil {
		return badRequest("File not provided.")
	}
	defer file.Close()
	if strings.TrimSpace(hdr.Filename) == "" {
		return badRequest("File name not provided.")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBody))
	if err != nil {
		return errFrom(err)
	}
	d := s.v.CipherData(itemID)
	if d == nil {
		return notFound()
	}
	if d.OrganizationID == nil && !s.v.HasPremium() {
		return errResp("Premium status is required to use this feature.")
	}
	c, err := s.v.CreateAttachment(q.r.Context(), itemID, hdr.Filename, data)
	if err != nil {
		return errFrom(err)
	}
	return success(c.ToCLI())
}

// --- templates (GET /object/template/{id}) ---

func (s *Server) getTemplate(id string) *Response {
	var t any
	switch strings.ToLower(id) {
	case "item":
		t = vault.NewOMap().Set("type", 1).Set("name", "Item name").Set("favorite", false).Set("reprompt", 0).
			Set("notes", "Some notes about this item.").Set("fields", []any{}).Set("passwordHistory", []any{})
	case "item.field":
		t = vault.NewOMap().Set("type", 0).Set("name", "Field name").Set("value", "Some value")
	case "item.login":
		t = vault.NewOMap().Set("uris", []any{}).Set("username", "jdoe").Set("password", "myp@ssword123").
			Set("totp", "JBSWY3DPEHPK3PXP").Set("fido2Credentials", []any{})
	case "item.login.uri":
		t = vault.NewOMap().Set("uri", "https://google.com")
	case "item.card":
		t = vault.NewOMap().Set("cardholderName", "John Doe").Set("brand", "visa").Set("number", "4242424242424242").
			Set("expMonth", "04").Set("expYear", "2023").Set("code", "123")
	case "item.identity":
		t = vault.NewOMap().Set("title", "Mr").Set("firstName", "John").Set("middleName", "William").
			Set("lastName", "Doe").Set("address1", "123 Any St").Set("address2", "Apt #123").
			Set("city", "New York").Set("state", "NY").Set("postalCode", "10001").Set("country", "US").
			Set("company", "Acme Inc.").Set("email", "john@company.com").Set("phone", "5555551234").
			Set("ssn", "000-123-4567").Set("username", "jdoe").Set("passportNumber", "US-123456789").
			Set("licenseNumber", "D123-12-123-12333")
	case "item.securenote":
		t = vault.NewOMap().Set("type", 0)
	case "item.bankaccount":
		return badRequest("Bank account item type is not available.")
	case "item.driverslicense":
		return badRequest("Driver's license item type is not available.")
	case "item.passport":
		return badRequest("Passport item type is not available.")
	case "folder":
		t = vault.NewOMap().Set("name", "Folder name")
	case "collection":
		t = vault.NewOMap().Set("organizationId", "00000000-0000-0000-0000-000000000000").
			Set("name", "Collection name").Set("externalId", nil)
	case "item-collections":
		t = []string{"collection-id1", "collection-id2"}
	case "org-collection":
		sel := func() []any {
			one := func() *vault.OMap {
				return vault.NewOMap().Set("id", "00000000-0000-0000-0000-000000000000").
					Set("readOnly", false).Set("hidePasswords", false).Set("manage", false)
			}
			return []any{one(), one()}
		}
		t = vault.NewOMap().Set("organizationId", "00000000-0000-0000-0000-000000000000").
			Set("name", "Collection name").Set("externalId", nil).Set("groups", sel()).Set("users", sel())
	case "send.file", "send.text":
		t = errResp("Invalid template object. Use `bw send template " + id + "` instead.")
	default:
		return badRequest("Unknown template object.")
	}
	return success(templateResponse(t))
}
