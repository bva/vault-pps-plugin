package pleasant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

type mockPPSServer struct {
	server *httptest.Server

	mu        sync.Mutex
	root      CredentialGroup
	passwords map[string]string
	token     string

	authCalls  int32
	treeCalls  int32
	pwdCalls   int32
}

func newMockPPSServer(t *testing.T) *mockPPSServer {
	t.Helper()

	m := &mockPPSServer{
		token: "mock-oauth-token-1",
		passwords: map[string]string{
			"cred-1": "s3cret-abb01p",
			"cred-2": "dup-pass-1",
			"cred-3": "dup-pass-2",
			"cred-4": "username-only-pass",
		},
		root: CredentialGroup{
			Id:   "root-id",
			Name: "Root",
			Children: []CredentialGroup{
				{
					Id:       "grp-shared",
					Name:     "Shared_Folders",
					ParentId: "root-id",
					Children: []CredentialGroup{
						{
							Id:       "grp-db1",
							Name:     "abb01p",
							ParentId: "grp-shared",
							Notes:    "Primary DB folder",
							Credentials: []Credential{
								{
									Id:       "cred-1",
									Name:     "ABBPRD_app",
									Username: "ABBPRD",
									GroupId:  "grp-db1",
									Url:      "jdbc:oracle:thin:@abb01p:1521/ABBPRD",
									Notes:    "App schema",
									Created:  "2025-01-01T00:00:00Z",
									Modified: "2025-01-02T00:00:00Z",
									Expires:  "2027-01-01T00:00:00Z",
									CustomUserFields: map[string]string{
										"Env": "prod",
									},
									Attachments: []Attachment{
										{
											CredentialObjectId: "cred-1",
											FileName:           "tnsnames.ora",
											FileData:           "ABB01P = (DESCRIPTION = ...)",
										},
									},
								},
								{
									Id:       "cred-2",
									Name:     "DUP_ENTRY",
									Username: "DUP_USER_1",
									GroupId:  "grp-db1",
								},
								{
									Id:       "cred-3",
									Name:     "DUP_ENTRY",
									Username: "DUP_USER_2",
									GroupId:  "grp-db1",
								},
								{
									Id:       "cred-4",
									Name:     "",
									Username: "FALLBACK_USERNAME",
									GroupId:  "grp-db1",
								},
							},
						},
					},
				},
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/OAuth2/Token":
			m.handleOAuthToken(w, r)
		case strings.HasPrefix(path, "/api/v4/rest/credentialgroup/"):
			m.handleCredentialGroup(w, r)
		case path == "/api/v4/rest/credentialgroup":
			m.handleCredentialGroupRoot(w, r)
		case strings.HasPrefix(path, "/api/v4/rest/credential/"):
			m.handleCredential(w, r)
		case path == "/api/v4/rest/credential":
			m.handleCredentialCreate(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	m.server = httptest.NewServer(handler)
	t.Cleanup(func() {
		m.server.Close()
	})
	return m
}

func (m *mockPPSServer) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&m.authCalls, 1)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	if r.FormValue("username") != "pps_admin" || r.FormValue("password") != "pps_pass" {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	tok := m.token
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(AuthSuccess{
		AccessToken: tok,
		TokenType:   "bearer",
		ExpiresIn:   3600,
	})
}

func (m *mockPPSServer) handleCredentialGroup(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v4/rest/credentialgroup/")
	id = strings.TrimSuffix(id, "/")

	switch r.Method {
	case http.MethodGet:
		atomic.AddInt32(&m.treeCalls, 1)
		m.mu.Lock()
		defer m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if id == "" {
			_ = json.NewEncoder(w).Encode(m.root)
			return
		}
		grp := findGroupByID(&m.root, id)
		if grp == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(grp)

	case http.MethodPut:
		var updated CredentialGroup
		if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		grp := findGroupByID(&m.root, id)
		if grp != nil {
			grp.Name = updated.Name
			grp.Notes = updated.Notes
		}
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)

	case http.MethodDelete:
		m.mu.Lock()
		deleteGroupByID(&m.root, id)
		m.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}
}

func (m *mockPPSServer) handleCredentialGroupRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var newGrp CredentialGroup
	if err := json.NewDecoder(r.Body).Decode(&newGrp); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	if newGrp.Id == "" {
		newGrp.Id = "grp-created"
	}
	parent := findGroupByID(&m.root, newGrp.ParentId)
	if parent != nil {
		parent.Children = append(parent.Children, newGrp)
	}
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(newGrp.Id)
}

func (m *mockPPSServer) handleCredentialCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var cred Credential
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	if cred.Id == "" {
		cred.Id = "cred-created"
	}
	m.passwords[cred.Id] = cred.Password
	cred.Password = ""
	grp := findGroupByID(&m.root, cred.GroupId)
	if grp != nil {
		grp.Credentials = append(grp.Credentials, cred)
	}
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cred.Id)
}

func (m *mockPPSServer) handleCredential(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v4/rest/credential/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")

	if len(parts) == 2 && parts[1] == "password" && r.Method == http.MethodGet {
		atomic.AddInt32(&m.pwdCalls, 1)
		credID := parts[0]
		m.mu.Lock()
		pwd := m.passwords[credID]
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pwd)
		return
	}

	credID := parts[0]
	switch r.Method {
	case http.MethodGet:
		m.mu.Lock()
		cred := findCredentialByID(&m.root, credID)
		m.mu.Unlock()
		if cred == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cred)

	case http.MethodPut:
		var updated Credential
		if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		cred := findCredentialByID(&m.root, credID)
		if cred != nil {
			if updated.Password != "" {
				m.passwords[credID] = updated.Password
			}
			updated.Password = ""
			*cred = updated
		}
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)

	case http.MethodDelete:
		m.mu.Lock()
		deleteCredentialByID(&m.root, credID)
		delete(m.passwords, credID)
		m.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}
}

func findGroupByID(g *CredentialGroup, id string) *CredentialGroup {
	if g.Id == id {
		return g
	}
	for i := range g.Children {
		if found := findGroupByID(&g.Children[i], id); found != nil {
			return found
		}
	}
	return nil
}

func deleteGroupByID(g *CredentialGroup, id string) bool {
	for i := range g.Children {
		if g.Children[i].Id == id {
			g.Children = append(g.Children[:i], g.Children[i+1:]...)
			return true
		}
		if deleteGroupByID(&g.Children[i], id) {
			return true
		}
	}
	return false
}

func findCredentialByID(g *CredentialGroup, id string) *Credential {
	for i := range g.Credentials {
		if g.Credentials[i].Id == id {
			return &g.Credentials[i]
		}
	}
	for i := range g.Children {
		if found := findCredentialByID(&g.Children[i], id); found != nil {
			return found
		}
	}
	return nil
}

func deleteCredentialByID(g *CredentialGroup, id string) bool {
	for i := range g.Credentials {
		if g.Credentials[i].Id == id {
			g.Credentials = append(g.Credentials[:i], g.Credentials[i+1:]...)
			return true
		}
	}
	for i := range g.Children {
		if deleteCredentialByID(&g.Children[i], id) {
			return true
		}
	}
	return false
}

func setupTestBackend(t *testing.T, ppsURL string) (*backend, logical.Storage) {
	t.Helper()
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	b := Backend()
	if err := b.Setup(ctx, &logical.BackendConfig{StorageView: storage}); err != nil {
		t.Fatalf("failed to setup backend: %v", err)
	}

	if ppsURL != "" {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/access",
			Storage:   storage,
			Data: map[string]interface{}{
				"url":       ppsURL,
				"user_name": "pps_admin",
				"password":  "pps_pass",
			},
		}
		resp, err := b.HandleRequest(ctx, req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("failed to write config/access: err=%v resp=%v", err, resp)
		}
	}

	return b, storage
}

func TestConfigAccessLifecycle(t *testing.T) {
	ctx := context.Background()
	b, storage := setupTestBackend(t, "")

	// 1. Reading before configuration returns a logical error response
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/access",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, readReq)
	if err != nil {
		t.Fatalf("unexpected error on unconfigured config/access read: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response when config/access is missing, got: %#v", resp)
	}

	// 2. Write config/access and read it back
	writeReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/access",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":       "https://pps.example.com",
			"user_name": "pps_user",
			"password":  "pps_secret",
		},
	}
	if _, err := b.HandleRequest(ctx, writeReq); err != nil {
		t.Fatalf("failed writing config/access: %v", err)
	}

	resp, err = b.HandleRequest(ctx, readReq)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("failed reading configured config/access: err=%v resp=%#v", err, resp)
	}
	if resp.Data["url"] != "https://pps.example.com" ||
		resp.Data["user_name"] != "pps_user" ||
		resp.Data["password"] != "pps_secret" {
		t.Fatalf("unexpected config/access data: %#v", resp.Data)
	}
}

func TestListAndTreeCaching(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	// 1. List root folder
	rootListResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "",
		Storage:   storage,
	})
	if err != nil || rootListResp == nil {
		t.Fatalf("failed listing root: err=%v resp=%#v", err, rootListResp)
	}
	keys := rootListResp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "Shared_Folders/" {
		t.Fatalf("expected [Shared_Folders/], got: %v", keys)
	}

	// 2. List nested database folder (verifying duplicate disambiguation and fallback to Username)
	dbListResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "Shared_Folders/abb01p",
		Storage:   storage,
	})
	if err != nil || dbListResp == nil {
		t.Fatalf("failed listing Shared_Folders/abb01p: err=%v resp=%#v", err, dbListResp)
	}
	dbKeys := dbListResp.Data["keys"].([]string)
	expected := map[string]bool{
		"ABBPRD_app":        true,
		"DUP_ENTRY[cred-2]": true,
		"DUP_ENTRY[cred-3]": true,
		"FALLBACK_USERNAME": true,
	}
	if len(dbKeys) != len(expected) {
		t.Fatalf("expected %d keys, got %v", len(expected), dbKeys)
	}
	for _, k := range dbKeys {
		if !expected[k] {
			t.Errorf("unexpected key in list response: %q", k)
		}
	}

	// Verify tree was fetched only once across multiple operations
	if got := atomic.LoadInt32(&mock.treeCalls); got != 1 {
		t.Errorf("expected 1 tree fetch call due to caching, got %d", got)
	}
	if got := atomic.LoadInt32(&mock.authCalls); got != 1 {
		t.Errorf("expected 1 OAuth login call, got %d", got)
	}

	// 3. Listing a credential leaf or missing path returns ErrUnsupportedPath
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
	})
	if err != logical.ErrUnsupportedPath {
		t.Errorf("expected ErrUnsupportedPath when listing a credential leaf, got: %v", err)
	}
}

func TestReadCredentialAndExistenceCheck(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	// 1. Read full credential by Name (including CustomUserFields and Attachments)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
	})
	if err != nil || resp == nil {
		t.Fatalf("failed reading credential by Name: err=%v resp=%#v", err, resp)
	}
	if resp.Data["Id"] != "cred-1" ||
		resp.Data["Name"] != "ABBPRD_app" ||
		resp.Data["Username"] != "ABBPRD" ||
		resp.Data["Password"] != "s3cret-abb01p" ||
		resp.Data["Url"] != "jdbc:oracle:thin:@abb01p:1521/ABBPRD" ||
		resp.Data["Notes"] != "App schema" ||
		resp.Data["Custom:Env"] != "prod" ||
		resp.Data["Attachment:tnsnames.ora"] != "ABB01P = (DESCRIPTION = ...)" {
		t.Fatalf("unexpected credential data: %#v", resp.Data)
	}

	// 2. Read credential by Username fallback and by disambiguated Name[Id]
	dupResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/DUP_ENTRY[cred-3]",
		Storage:   storage,
	})
	if err != nil || dupResp == nil || dupResp.Data["Password"] != "dup-pass-2" {
		t.Fatalf("failed reading disambiguated credential: err=%v resp=%#v", err, dupResp)
	}

	userResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/FALLBACK_USERNAME",
		Storage:   storage,
	})
	if err != nil || userResp == nil || userResp.Data["Password"] != "username-only-pass" {
		t.Fatalf("failed reading credential by Username: err=%v resp=%#v", err, userResp)
	}

	// 3. ExistenceCheck returns true for existing credential/group and false for missing path
	exists, err := b.pathExistenceCheck(ctx, &logical.Request{
		Path:    "Shared_Folders/abb01p/ABBPRD_app",
		Storage: storage,
	}, nil)
	if err != nil || !exists {
		t.Errorf("expected pathExistenceCheck=true for existing credential, got exists=%v err=%v", exists, err)
	}

	exists, err = b.pathExistenceCheck(ctx, &logical.Request{
		Path:    "Shared_Folders/abb01p/NON_EXISTENT",
		Storage: storage,
	}, nil)
	if err != nil || exists {
		t.Errorf("expected pathExistenceCheck=false for missing path, got exists=%v err=%v", exists, err)
	}
}

func TestCredentialAndGroupCRUD(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	// 1. Create a new credential in Shared_Folders/abb01p
	createResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "Shared_Folders/abb01p/NEW_SCHEMA",
		Storage:   storage,
		Data: map[string]interface{}{
			"Username":        "NEW_SCHEMA_USER",
			"Password":        "new-pass-123",
			"Notes":           "Created by test",
			"Custom:Tier":     "gold",
			"Attachment:cert": "PEM_DATA",
		},
	})
	if err != nil || createResp == nil {
		t.Fatalf("failed creating credential: err=%v resp=%#v", err, createResp)
	}
	if createResp.Data["Id"] != "cred-created" ||
		createResp.Data["Username"] != "NEW_SCHEMA_USER" ||
		createResp.Data["Password"] != "new-pass-123" ||
		createResp.Data["Custom:Tier"] != "gold" ||
		createResp.Data["Attachment:cert"] != "PEM_DATA" {
		t.Fatalf("unexpected created credential response: %#v", createResp.Data)
	}

	// 2. Update the credential (modify Notes, remove Custom:Tier by passing "", keep existing password)
	updateResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "Shared_Folders/abb01p/NEW_SCHEMA",
		Storage:   storage,
		Data: map[string]interface{}{
			"Notes":       "Updated notes",
			"Custom:Tier": "",
			"Custom:Role": "readonly",
		},
	})
	if err != nil || updateResp == nil {
		t.Fatalf("failed updating credential: err=%v resp=%#v", err, updateResp)
	}
	if updateResp.Data["Notes"] != "Updated notes" ||
		updateResp.Data["Password"] != "new-pass-123" ||
		updateResp.Data["Custom:Role"] != "readonly" {
		t.Fatalf("unexpected updated credential data: %#v", updateResp.Data)
	}
	if _, stillHasTier := updateResp.Data["Custom:Tier"]; stillHasTier {
		t.Errorf("expected Custom:Tier to be deleted when empty string is passed")
	}

	// 3. Create a child group with Group="true", update it, and delete both credential and group
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "Shared_Folders/new_cluster",
		Storage:   storage,
		Data: map[string]interface{}{
			"Group": "true",
			"Notes": "New DB cluster group",
		},
	})
	if err != nil {
		t.Fatalf("failed creating credential group: %v", err)
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "Shared_Folders/new_cluster",
		Storage:   storage,
		Data: map[string]interface{}{
			"Notes": "Updated cluster notes",
		},
	})
	if err != nil {
		t.Fatalf("failed updating credential group: %v", err)
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "Shared_Folders/abb01p/NEW_SCHEMA",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("failed deleting credential: %v", err)
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "Shared_Folders/new_cluster",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("failed deleting credential group: %v", err)
	}

	// Verify NEW_SCHEMA is gone after delete
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/NEW_SCHEMA",
		Storage:   storage,
	})
	if err != logical.ErrUnsupportedPath {
		t.Errorf("expected ErrUnsupportedPath after deleting credential, got: %v", err)
	}
}
