package vault

import "testing"

func sp(s string) *string { return &s }

func TestAdjustPasswordHistory(t *testing.T) {
	existing := &CipherView{
		Type:  CipherTypeLogin,
		Login: &LoginView{Password: sp("old")},
		Fields: []FieldView{
			{Name: sp("api"), Value: sp("k1"), Type: FieldTypeHidden},
			{Name: sp("keep"), Value: sp("same"), Type: FieldTypeHidden},
		},
		PasswordHistory: []PasswordHistoryView{{Password: "h1"}, {Password: "h2"}, {Password: "h3"}, {Password: "h4"}},
	}
	model := CloneCipherView(existing)
	model.Login.Password = sp("new")
	model.Fields[0].Value = sp("k2")
	adjustPasswordHistory(model, existing)
	got := []string{}
	for _, h := range model.PasswordHistory {
		got = append(got, h.Password)
	}
	want := []string{"api: k1", "old", "h1", "h2", "h3"}
	if len(got) != len(want) {
		t.Fatalf("history = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("history = %v, want %v", got, want)
		}
	}
	if model.Login.PasswordRevisionDate == nil {
		t.Fatal("passwordRevisionDate not set on password change")
	}

	unchanged := CloneCipherView(existing)
	adjustPasswordHistory(unchanged, existing)
	if len(unchanged.PasswordHistory) != 4 {
		t.Fatalf("unchanged item gained history: %d", len(unchanged.PasswordHistory))
	}
}

func TestApplyCipherExportKeepsCipherKeyAndMergesCollections(t *testing.T) {
	key := "2.abc|def|ghi"
	existing := &CipherView{ID: "x", Type: CipherTypeLogin, Key: &key, CollectionIDs: []string{"c1"}, OrganizationID: sp("org")}
	v, err := ApplyCipherExport(map[string]any{
		"type": float64(1), "name": "n", "collectionIds": []any{"c2", "c1"},
		"login": map[string]any{"username": "u", "uris": []any{map[string]any{"uri": "https://a", "match": float64(3)}}},
	}, CloneCipherView(existing))
	if err != nil {
		t.Fatal(err)
	}
	if v.Key == nil || *v.Key != key {
		t.Fatal("cipher key dropped on edit")
	}
	if len(v.CollectionIDs) != 2 || v.CollectionIDs[0] != "c1" || v.CollectionIDs[1] != "c2" {
		t.Fatalf("collections = %v", v.CollectionIDs)
	}
	if *v.OrganizationID != "org" || *v.Login.URIs[0].Match != 3 || v.FolderID != nil {
		t.Fatalf("unexpected view %+v", v)
	}
	if _, err := ApplyCipherExport(map[string]any{"type": float64(5), "sshKey": map[string]any{"privateKey": "p"}}, nil); err == nil {
		t.Fatal("expected ssh key validation error")
	}
}
