package server

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/crypto"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/generator"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/totp"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/vault"
)

// --- search helpers (SearchService.searchCiphersBasic / CliUtils.search*) ---

func searchCiphersBasic(ciphers []*vault.CipherView, query string) []*vault.CipherView {
	terms := strings.Fields(vault.NormalizeSearch(strings.TrimSpace(query)))
	out := []*vault.CipherView{}
	for _, c := range ciphers {
		ok := true
		for _, term := range terms {
			if !cipherMatchesTerm(c, term) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, c)
		}
	}
	return out
}

func cipherMatchesTerm(c *vault.CipherView, term string) bool {
	idx := c.Search()
	if strings.Contains(idx.Name, term) {
		return true
	}
	if len(term) >= 8 && strings.HasPrefix(c.ID, term) {
		return true
	}
	if idx.SubTitle != "" && strings.Contains(idx.SubTitle, term) {
		return true
	}
	for _, h := range idx.Hosts {
		if strings.Contains(h, term) {
			return true
		}
	}
	return idx.Notes != "" && strings.Contains(idx.Notes, term)
}

func searchByName[T any](items []T, search string, name func(T) string) []T {
	s := strings.ToLower(search)
	out := []T{}
	for _, it := range items {
		if strings.Contains(strings.ToLower(name(it)), s) {
			out = append(out, it)
		}
	}
	return out
}

// --- restricted item types ---

type restriction struct {
	cipherType   int
	allowViewOrg map[string]bool
}

func (s *Server) restrictions() []restriction {
	pols := s.v.Policies(vault.PolicyTypeRestrictedItemTypes, true)
	if len(pols) == 0 {
		return nil
	}
	typesOf := func(p vault.PolicyData) []int {
		var t []int
		if err := jsonUnmarshal(p.Data, &t); err != nil || t == nil {
			return []int{vault.CipherTypeCard}
		}
		return t
	}
	all := map[int]bool{}
	for _, p := range pols {
		for _, t := range typesOf(p) {
			all[t] = true
		}
	}
	orgs := s.v.Organizations()
	var out []restriction
	for t := range all {
		r := restriction{cipherType: t, allowViewOrg: map[string]bool{}}
		for _, o := range orgs {
			var orgPol *vault.PolicyData
			for i := range pols {
				if pols[i].OrganizationID == o.ID {
					orgPol = &pols[i]
				}
			}
			if orgPol == nil {
				r.allowViewOrg[o.ID] = true
				continue
			}
			restricted := false
			for _, rt := range typesOf(*orgPol) {
				if rt == t {
					restricted = true
				}
			}
			if !restricted {
				r.allowViewOrg[o.ID] = true
			}
		}
		out = append(out, r)
	}
	return out
}

func isRestricted(c *vault.CipherView, rs []restriction) bool {
	for _, r := range rs {
		if r.cipherType != c.Type {
			continue
		}
		if c.OrganizationID != nil {
			return !r.allowViewOrg[*c.OrganizationID]
		}
		return true
	}
	return false
}

func filterRestricted(cs []*vault.CipherView, rs []restriction) []*vault.CipherView {
	if len(rs) == 0 {
		return cs
	}
	out := make([]*vault.CipherView, 0, len(cs))
	for _, c := range cs {
		if !isRestricted(c, rs) {
			out = append(out, c)
		}
	}
	return out
}

// --- GET /object/{object}/{id} ---

func (s *Server) get(q *request) *Response {
	object := q.r.PathValue("object")
	id := strings.ToLower(q.r.PathValue("id"))
	if object == "send" {
		return s.sendGet(id)
	}
	switch strings.ToLower(object) {
	case "item":
		r, _ := s.getCipher(id, nil)
		return r
	case "username":
		return s.getLoginField(id, "username")
	case "password":
		return s.getLoginField(id, "password")
	case "uri":
		return s.getLoginField(id, "uri")
	case "totp":
		return s.getTotp(id)
	case "notes":
		r, c := s.getCipher(id, func(c *vault.CipherView) bool { return !isNullOrWhitespace(c.Notes) })
		if c == nil {
			return r
		}
		if isNullOrWhitespace(c.Notes) {
			return errResp("No notes available for this item.")
		}
		return success(stringResponse(*c.Notes))
	case "exposed":
		return s.getExposed(id)
	case "attachment":
		return s.getAttachment(q, id)
	case "folder":
		return s.getFolder(id)
	case "collection":
		return s.getCollection(id)
	case "org-collection":
		return s.getOrgCollection(q, id)
	case "organization":
		return s.getOrganization(id)
	case "template":
		return s.getTemplate(id)
	case "fingerprint":
		return s.getFingerprint(q, id)
	}
	return badRequest("Unknown object.")
}

// getCipherView returns a single cipher, multiple matches, or nothing.
func (s *Server) getCipherView(id string) (*vault.CipherView, []*vault.CipherView) {
	if isGUID(id) {
		return s.v.Cipher(id), nil
	}
	if strings.TrimSpace(id) == "" {
		return nil, nil
	}
	var active []*vault.CipherView
	for _, c := range s.v.Ciphers() {
		if !c.IsDeleted() && !c.IsArchived() {
			active = append(active, c)
		}
	}
	found := searchCiphersBasic(active, id)
	if len(found) > 1 {
		return nil, found
	}
	if len(found) == 1 {
		return found[0], nil
	}
	return nil, nil
}

func (s *Server) getCipher(id string, filter func(*vault.CipherView) bool) (*Response, *vault.CipherView) {
	single, multi := s.getCipherView(id)
	if single == nil && multi == nil {
		return notFound(), nil
	}
	rs := s.restrictions()
	if multi != nil {
		multi = filterRestricted(multi, rs)
		if len(multi) == 0 {
			return errResp("Access to this item type is restricted by organizational policy."), nil
		}
		if filter != nil {
			var f []*vault.CipherView
			for _, c := range multi {
				if filter(c) {
					f = append(f, c)
				}
			}
			multi = f
		}
		if len(multi) == 0 {
			return notFound(), nil
		}
		if len(multi) > 1 {
			ids := make([]string, 0, len(multi))
			for _, c := range multi {
				ids = append(ids, c.ID)
			}
			return multipleResults(ids), nil
		}
		single = multi[0]
	} else {
		if isRestricted(single, rs) {
			return errResp("Access to this item type is restricted by organizational policy."), nil
		}
		if filter != nil && !filter(single) {
			return notFound(), nil
		}
	}
	return success(single.ToCLI()), single
}

func loginFieldValue(c *vault.CipherView, field string) string {
	if c.Type != vault.CipherTypeLogin || c.Login == nil {
		return ""
	}
	switch field {
	case "username":
		return strings.TrimSpace(derefStr(c.Login.Username))
	case "password":
		return strings.TrimSpace(derefStr(c.Login.Password))
	case "totp":
		return strings.TrimSpace(derefStr(c.Login.Totp))
	case "uri":
		if len(c.Login.URIs) > 0 {
			return derefStr(c.Login.URIs[0].URI)
		}
	}
	return ""
}

// visibleLoginField applies the CipherResponse redaction for viewPassword=false.
func visibleLoginField(c *vault.CipherView, field string) string {
	if !c.ViewPassword && (field == "password" || field == "totp") {
		return ""
	}
	return loginFieldValue(c, field)
}

func (s *Server) getLoginField(id, field string) *Response {
	r, c := s.getCipher(id, func(c *vault.CipherView) bool { return loginFieldValue(c, field) != "" })
	if c == nil {
		return r
	}
	if c.Type != vault.CipherTypeLogin {
		return badRequest("Not a login.")
	}
	if visibleLoginField(c, field) == "" {
		return errResp(fmt.Sprintf("No %s available for this login.", field))
	}
	switch field {
	case "username":
		return success(stringResponse(*c.Login.Username))
	case "password":
		return success(stringResponse(*c.Login.Password))
	default:
		return success(stringResponse(*c.Login.URIs[0].URI))
	}
}

func (s *Server) getTotp(id string) *Response {
	r, c := s.getCipher(id, func(c *vault.CipherView) bool { return loginFieldValue(c, "totp") != "" })
	if c == nil {
		return r
	}
	if c.Type != vault.CipherTypeLogin {
		return badRequest("Not a login.")
	}
	if visibleLoginField(c, "totp") == "" {
		return errResp("No TOTP available for this login.")
	}
	code, err := totp.Generate(*c.Login.Totp, time.Now())
	if err != nil || code == "" {
		return errResp("Couldn't generate TOTP code.")
	}
	if !s.v.HasPremium() {
		if c.OrganizationID == nil || !c.OrganizationUseTotp {
			return errResp("Premium status is required to use this feature.")
		}
	}
	return success(stringResponse(code))
}

func (s *Server) getExposed(id string) *Response {
	r := s.getLoginField(id, "password")
	if !r.Success {
		return r
	}
	pw := r.Data.(*vault.OMap).Get("data").(string)
	sum := sha1.Sum([]byte(pw))
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	req, _ := http.NewRequest(http.MethodGet, "https://api.pwnedpasswords.com/range/"+h[:5], nil)
	resp, err := s.v.Client.HTTP.Do(req)
	if err != nil {
		return errFrom(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	count := 0
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) == 2 && parts[0] == h[5:] {
			count, _ = strconv.Atoi(parts[1])
			break
		}
	}
	return success(stringResponse(strconv.Itoa(count)))
}

func (s *Server) getAttachment(q *request, id string) *Response {
	itemID := strings.ToLower(q.optStr("itemid", "itemId"))
	if itemID == "" {
		return badRequest("--itemid <itemid> required.")
	}
	r, _ := s.getCipher(itemID, nil)
	if !r.Success {
		return r
	}
	c, multi := s.getCipherView(itemID)
	if c == nil || multi != nil || len(c.Attachments) == 0 {
		return errResp("No attachments available for this item.")
	}
	var atts []vault.AttachmentView
	for _, a := range c.Attachments {
		if strings.ToLower(a.ID) == id || (a.FileName != nil && strings.Contains(strings.ToLower(*a.FileName), id)) {
			atts = append(atts, a)
		}
	}
	if len(atts) == 0 {
		return errResp("Attachment `" + id + "` was not found.")
	}
	var exact []vault.AttachmentView
	for _, a := range atts {
		if a.FileName != nil && strings.ToLower(*a.FileName) == id {
			exact = append(exact, a)
		}
	}
	if len(exact) == 1 {
		atts = exact
	}
	if len(atts) > 1 {
		ids := []string{}
		for _, a := range atts {
			ids = append(ids, a.ID)
		}
		return multipleResults(ids)
	}
	if !s.v.HasPremium() && c.OrganizationID == nil {
		return errResp("Premium status is required to use this feature.")
	}
	data, err := s.v.DownloadAttachment(q.r.Context(), c.ID, atts[0])
	if err != nil {
		return errFrom(err)
	}
	name := derefStr(atts[0].FileName)
	if name == "" {
		name = fmt.Sprintf("BitwardenAttachment-%d", time.Now().UnixMilli())
	}
	return fileResponse(data, path.Base(name))
}

func (s *Server) getFolder(id string) *Response {
	var f *vault.FolderView
	if isGUID(id) {
		f = s.v.Folder(id)
	} else if strings.TrimSpace(id) != "" {
		found := searchByName(s.v.Folders(), id, func(f *vault.FolderView) string { return f.Name })
		if len(found) > 1 {
			ids := []string{}
			for _, x := range found {
				ids = append(ids, x.ID)
			}
			return multipleResults(ids)
		}
		if len(found) == 1 {
			f = found[0]
		}
	}
	if f == nil {
		return notFound()
	}
	return success(f.ToCLI())
}

func (s *Server) getCollection(id string) *Response {
	var c *vault.CollectionView
	cols := s.v.Collections()
	if isGUID(id) {
		for _, x := range cols {
			if x.ID == id {
				c = x
			}
		}
	} else if strings.TrimSpace(id) != "" {
		found := searchByName(cols, id, func(c *vault.CollectionView) string { return c.Name })
		if len(found) > 1 {
			ids := []string{}
			for _, x := range found {
				ids = append(ids, x.ID)
			}
			return multipleResults(ids)
		}
		if len(found) == 1 {
			c = found[0]
		}
	}
	if c == nil {
		return notFound()
	}
	return success(c.ToCLI("collection", true))
}

func selectionList(in []vault.SelectionReadOnly) []any {
	if in == nil {
		return nil
	}
	out := make([]any, 0, len(in))
	for _, g := range in {
		out = append(out, vault.NewOMap().Set("id", g.ID).Set("readOnly", g.ReadOnly).Set("hidePasswords", g.HidePasswords).Set("manage", g.Manage))
	}
	return out
}

func orgCollectionCLI(id, orgID, name string, externalID *string, groups, users []vault.SelectionReadOnly) *vault.OMap {
	cv := &vault.CollectionView{ID: id, OrganizationID: orgID, Name: name, ExternalID: externalID}
	return cv.ToCLI("org-collection", true).Set("groups", selectionList(groups)).Set("users", selectionList(users))
}

func (s *Server) getOrgCollection(q *request, id string) *Response {
	orgID := q.optStr("organizationid", "organizationId")
	if orgID == "" {
		return badRequest("`organizationid` option is required.")
	}
	if !isGUID(id) {
		return badRequest("`" + id + "` is not a GUID.")
	}
	if !isGUID(orgID) {
		return badRequest("`" + orgID + "` is not a GUID.")
	}
	orgKey := s.v.OrgKey(orgID)
	if orgKey == nil {
		return errResp("No encryption key for this organization.")
	}
	d, err := s.v.GetCollectionAccessDetails(q.r.Context(), orgID, id)
	if err != nil {
		return errFrom(err)
	}
	name, err := crypto.DecryptToString(orgKey, d.Name)
	if err != nil {
		name = "[error: cannot decrypt]"
	}
	return success(orgCollectionCLI(d.ID, d.OrganizationID, name, d.ExternalID, d.Groups, d.Users))
}

func (s *Server) getOrganization(id string) *Response {
	var o *vault.Organization
	orgs := s.v.Organizations()
	if isGUID(id) {
		for _, x := range orgs {
			if x.ID == id {
				o = x
			}
		}
	} else if strings.TrimSpace(id) != "" {
		found := searchByName(orgs, id, func(o *vault.Organization) string { return o.Name })
		if len(found) > 1 {
			ids := []string{}
			for _, x := range found {
				ids = append(ids, x.ID)
			}
			return multipleResults(ids)
		}
		if len(found) == 1 {
			o = found[0]
		}
	}
	if o == nil {
		return notFound()
	}
	return success(o.ToCLI())
}

func (s *Server) getFingerprint(q *request, id string) *Response {
	var pub []byte
	var material string
	if id == "me" {
		der, err := s.v.PublicKeyDER()
		if err != nil {
			return errFrom(err)
		}
		pub, material = der, s.v.UserID()
	} else if isGUID(id) {
		der, err := s.v.UserPublicKey(q.r.Context(), id)
		if err == nil {
			pub, material = der, id
		}
	}
	if pub == nil {
		return notFound()
	}
	return success(stringResponse(fingerprint(material, pub)))
}

func fingerprint(material string, publicKey []byte) string {
	kf := sha256.Sum256(publicKey)
	uf, err := crypto.HKDFExpandSHA256(kf[:], material, 32)
	if err != nil {
		return ""
	}
	return strings.Join(generator.FingerprintPhrase(uf), "-")
}

// --- GET /list/object/{object} ---

func (s *Server) list(q *request) *Response {
	object := q.r.PathValue("object")
	if object == "send" {
		return s.sendList(q)
	}
	switch strings.ToLower(object) {
	case "items":
		return s.listItems(q)
	case "folders":
		folders := s.v.Folders()
		if search := q.optStr("search"); strings.TrimSpace(search) != "" {
			folders = searchByName(folders, search, func(f *vault.FolderView) string { return f.Name })
		}
		items := make([]any, 0, len(folders))
		for _, f := range folders {
			items = append(items, f.ToCLI())
		}
		return success(listResponse(items))
	case "collections":
		cols := s.v.Collections()
		if orgID := q.opt("organizationid", "organizationId"); orgID != nil {
			var f []*vault.CollectionView
			for _, c := range cols {
				if c.OrganizationID == *orgID {
					f = append(f, c)
				}
			}
			cols = f
		}
		if search := q.optStr("search"); strings.TrimSpace(search) != "" {
			cols = searchByName(cols, search, func(c *vault.CollectionView) string { return c.Name })
		}
		items := make([]any, 0, len(cols))
		for _, c := range cols {
			items = append(items, c.ToCLI("collection", false))
		}
		return success(listResponse(items))
	case "org-collections":
		return s.listOrgCollections(q)
	case "org-members":
		return s.listOrgMembers(q)
	case "organizations":
		orgs := s.v.Organizations()
		if search := q.optStr("search"); strings.TrimSpace(search) != "" {
			orgs = searchByName(orgs, search, func(o *vault.Organization) string { return o.Name })
		}
		items := make([]any, 0, len(orgs))
		for _, o := range orgs {
			items = append(items, o.ToCLI())
		}
		return success(listResponse(items))
	}
	return badRequest("Unknown object.")
}

func (s *Server) listItems(q *request) *Response {
	trash := q.optBool("trash")
	archived := s.v.HasPremium() && q.optBool("archived")
	matchesState := func(c *vault.CipherView) bool {
		return trash == c.IsDeleted() && archived == c.IsArchived()
	}
	var ciphers []*vault.CipherView
	if u := q.optStr("url"); strings.TrimSpace(u) != "" {
		ciphers = ciphersForURL(s.v.Ciphers(), u, s.v.Domains())
	} else {
		ciphers = s.v.Ciphers()
	}
	folderID := q.opt("folderid", "folderId")
	collectionID := q.opt("collectionid", "collectionId")
	orgID := q.opt("organizationid", "organizationId")
	search := q.optStr("search")
	if folderID != nil || collectionID != nil || orgID != nil {
		var f []*vault.CipherView
		for _, c := range ciphers {
			if !matchesState(c) {
				continue
			}
			match := false
			if folderID != nil {
				if *folderID == "notnull" && c.FolderID != nil {
					match = true
				} else if *folderID == "null" && c.FolderID == nil {
					match = true
				} else if c.FolderID != nil && *c.FolderID == *folderID {
					match = true
				}
			}
			if !match && orgID != nil {
				if *orgID == "notnull" && c.OrganizationID != nil {
					match = true
				} else if *orgID == "null" && c.OrganizationID == nil {
					match = true
				} else if c.OrganizationID != nil && *c.OrganizationID == *orgID {
					match = true
				}
			}
			if !match && collectionID != nil {
				switch {
				case *collectionID == "notnull" && len(c.CollectionIDs) > 0:
					match = true
				case *collectionID == "null" && len(c.CollectionIDs) == 0:
					match = true
				default:
					for _, id := range c.CollectionIDs {
						if id == *collectionID {
							match = true
						}
					}
				}
			}
			if match {
				f = append(f, c)
			}
		}
		ciphers = f
	} else if strings.TrimSpace(search) == "" {
		var f []*vault.CipherView
		for _, c := range ciphers {
			if matchesState(c) {
				f = append(f, c)
			}
		}
		ciphers = f
	}
	if strings.TrimSpace(search) != "" {
		var f []*vault.CipherView
		for _, c := range ciphers {
			if matchesState(c) {
				f = append(f, c)
			}
		}
		ciphers = searchCiphersBasic(f, search)
	}
	ciphers = filterRestricted(ciphers, s.restrictions())
	items := make([]any, 0, len(ciphers))
	for _, c := range ciphers {
		items = append(items, c.ToCLI())
	}
	return success(listResponse(items))
}

func (s *Server) listOrgCollections(q *request) *Response {
	orgID := q.optStr("organizationid", "organizationId")
	if orgID == "" {
		return badRequest("`organizationid` option is required.")
	}
	if !isGUID(orgID) {
		return badRequest("`" + orgID + "` is not a GUID.")
	}
	org := s.v.Organization(orgID)
	if org == nil {
		return errResp("Organization not found.")
	}
	data, err := s.v.ListOrgCollections(q.r.Context(), orgID, org.CanViewAllCollections())
	if err != nil {
		return errFrom(err)
	}
	orgKey := s.v.OrgKey(orgID)
	if orgKey == nil {
		return errResp("Organization keys not found.")
	}
	cols := make([]*vault.CollectionView, 0, len(data))
	for i := range data {
		cols = append(cols, vault.DecryptCollection(&data[i], orgKey))
	}
	vault.SortByName(cols, func(c *vault.CollectionView) string { return c.Name })
	if search := q.optStr("search"); strings.TrimSpace(search) != "" {
		cols = searchByName(cols, search, func(c *vault.CollectionView) string { return c.Name })
	}
	items := make([]any, 0, len(cols))
	for _, c := range cols {
		items = append(items, c.ToCLI("collection", true))
	}
	return success(listResponse(items))
}

func (s *Server) listOrgMembers(q *request) *Response {
	orgID := q.optStr("organizationid", "organizationId")
	if orgID == "" {
		return badRequest("`organizationid` option is required.")
	}
	if !isGUID(orgID) {
		return badRequest("`" + orgID + "` is not a GUID.")
	}
	if s.v.Organization(orgID) == nil {
		return errResp("Organization not found.")
	}
	users, err := s.v.ListOrgUsers(q.r.Context(), orgID)
	if err != nil {
		return errFrom(err)
	}
	items := make([]any, 0, len(users))
	for _, u := range users {
		m := vault.NewOMap().Set("object", "org-member").Set("id", u.ID).Set("email", u.Email)
		if u.Name != nil {
			m.Set("name", *u.Name)
		}
		m.Set("status", u.Status).Set("type", u.Type).Set("twoFactorEnabled", u.TwoFactorEnabled)
		items = append(items, m)
	}
	return success(listResponse(items))
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
