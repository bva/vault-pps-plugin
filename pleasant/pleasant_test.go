package pleasant

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type mockPPSServer struct {
	server *httptest.Server

	mu        sync.Mutex
	root      CredentialGroup
	passwords map[string]string
	token     string

	enforceToken bool
	authStatus   int
	expiresIn    uint
	pwdStatus    int
	pwdRawBody   string
	pwdDelay     time.Duration

	authCalls  int32
	treeCalls  int32
	groupCalls int32
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

	m.mu.Lock()
	authStatus := m.authStatus
	tok := m.token
	exp := m.expiresIn
	m.mu.Unlock()
	if exp == 0 {
		exp = 3600
	}

	if authStatus != 0 && authStatus != http.StatusOK {
		http.Error(w, `{"error":"server_error"}`, authStatus)
		return
	}

	_ = r.ParseForm()
	if r.FormValue("username") != "pps_admin" || r.FormValue("password") != "pps_pass" {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(AuthSuccess{
		AccessToken: tok,
		TokenType:   "bearer",
		ExpiresIn:   exp,
	})
}

func (m *mockPPSServer) handleCredentialGroup(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v4/rest/credentialgroup/")
	id = strings.Trim(id, "/")

	switch r.Method {
	case http.MethodGet:
		m.mu.Lock()
		defer m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if id == "" {
			atomic.AddInt32(&m.treeCalls, 1)
			_ = json.NewEncoder(w).Encode(m.root)
			return
		}
		atomic.AddInt32(&m.groupCalls, 1)
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
		enforce := m.enforceToken
		expectedTok := m.token
		status := m.pwdStatus
		rawBody := m.pwdRawBody
		delay := m.pwdDelay
		pwd, exists := m.passwords[credID]
		m.mu.Unlock()

		if delay > 0 {
			time.Sleep(delay)
		}

		if status != 0 && status != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(rawBody))
			return
		}

		if enforce && r.Header.Get("Authorization") != expectedTok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"Message":"Authorization has been denied for this request."}`))
			return
		}

		if !exists {
			// Real PPS 7.8.2.0 returns HTTP 400 ("400 Cannot find the requested entry.") with empty body for missing entries
			w.WriteHeader(http.StatusBadRequest)
			return
		}

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
		resp.Data["password"] != "pps_secret" ||
		resp.Data["tree_ttl"] != 300 {
		t.Fatalf("unexpected config/access data: %#v", resp.Data)
	}

	// 3. Partial update of timing parameters preserves existing credentials
	updateTimingsReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/access",
		Storage:   storage,
		Data: map[string]interface{}{
			"tree_ttl": "10m",
		},
	}
	if _, err := b.HandleRequest(ctx, updateTimingsReq); err != nil {
		t.Fatalf("failed updating timing parameters in config/access: %v", err)
	}

	resp, err = b.HandleRequest(ctx, readReq)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("failed reading updated config/access: err=%v resp=%#v", err, resp)
	}
	if resp.Data["url"] != "https://pps.example.com" ||
		resp.Data["user_name"] != "pps_user" ||
		resp.Data["password"] != "pps_secret" ||
		resp.Data["tree_ttl"] != 600 {
		t.Fatalf("unexpected config/access data after partial update: %#v", resp.Data)
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

func TestPasswordReadReauthenticatesOn401(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	mock.enforceToken = true
	b, storage := setupTestBackend(t, mock.server.URL)

	// 1. Prime session and tree cache with mock-oauth-token-1
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "Shared_Folders/abb01p",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("failed initial list: %v", err)
	}

	// 2. Rotate server-side valid token so the cached token-1 receives HTTP 401 on /password,
	// while a fresh /OAuth2/Token login receives mock-oauth-token-2.
	mock.mu.Lock()
	mock.token = "mock-oauth-token-2"
	mock.mu.Unlock()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("expected read to recover from 401 via re-auth, got err=%v resp=%#v", err, resp)
	}
	if got := resp.Data["Password"]; got != "s3cret-abb01p" {
		t.Fatalf("expected Password=%q after 401 re-auth, got %q", "s3cret-abb01p", got)
	}
	if got := atomic.LoadInt32(&mock.authCalls); got != 2 {
		t.Errorf("expected 2 OAuth token calls (initial + 401 re-auth), got %d", got)
	}
}

func TestPasswordReadReturnsErrorOnHTTPError(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	// Prime tree cache, then simulate HTTP 500 from PPS on /password
	mock.mu.Lock()
	mock.pwdStatus = http.StatusInternalServerError
	mock.pwdRawBody = `{"Message":"An error has occurred."}`
	mock.mu.Unlock()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatalf("expected error when PPS returns HTTP 500 on /password, got successful response with Password=%q", resp.Data["Password"])
	}
}

func TestPasswordReadUnmarshalsEscapedJSONCharacters(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	rawPassword := `p@ss"w\ord`
	mock.passwords["cred-1"] = rawPassword

	b, storage := setupTestBackend(t, mock.server.URL)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
	})
	if err != nil || resp == nil {
		t.Fatalf("unexpected error reading credential: err=%v resp=%#v", err, resp)
	}
	if got := resp.Data["Password"]; got != rawPassword {
		t.Fatalf("expected JSON-unmarshaled Password=%q, got %q", rawPassword, got)
	}
}

func TestPasswordReadReturnsErrorWhen401PersistsAfterReauth(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	// Prime tree cache first
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "Shared_Folders/abb01p",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("failed initial list: %v", err)
	}

	// Simulate per-entry ACL denial in PPS: /password returns 401 even after re-authenticating
	mock.mu.Lock()
	mock.pwdStatus = http.StatusUnauthorized
	mock.pwdRawBody = `{"Message":"Authorization has been denied for this request."}`
	mock.mu.Unlock()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatalf("expected error on persistent 401, got Password=%q", resp.Data["Password"])
	}
	if got := atomic.LoadInt32(&mock.authCalls); got != 2 {
		t.Errorf("expected exactly 1 re-auth attempt (total 2 authCalls), got %d", got)
	}
}

func TestFailedReauthDoesNotOverwriteValidToken(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	mock.enforceToken = true
	mock.expiresIn = 2 //ExpiresIn/2 = 1s so background reauth fires after 1 tick
	b, storage := setupTestBackend(t, mock.server.URL)

	// 1. Prime session with valid mock-oauth-token-1
	p, err := b.Session(ctx, storage)
	if err != nil || p == nil {
		t.Fatalf("failed getting initial session: err=%v", err)
	}

	// 2. Simulate transient /OAuth2/Token outage (HTTP 503) when background timer fires
	mock.mu.Lock()
	mock.authStatus = http.StatusServiceUnavailable
	mock.mu.Unlock()

	time.Sleep(1200 * time.Millisecond)

	// 3. Existing valid token in p.auth must still be preserved so reads succeed
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.Data["Password"] != "s3cret-abb01p" {
		t.Fatalf("expected read with preserved token to succeed, got err=%v resp=%#v", err, resp)
	}
}

func TestSessionReturnsErrorWhenInitialLoginFails(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	mock.mu.Lock()
	mock.authStatus = http.StatusUnauthorized
	mock.mu.Unlock()

	b, storage := setupTestBackend(t, mock.server.URL)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatalf("expected error when initial OAuth login fails, got resp=%#v", resp)
	}
}

func TestCacheMissDoesNotQueryPPS(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	// 1. Prime initial root tree cache
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "Shared_Folders/abb01p",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("failed initial list: %v", err)
	}
	if got := atomic.LoadInt32(&mock.treeCalls); got != 1 {
		t.Fatalf("expected 1 initial root tree fetch, got %d", got)
	}

	// 2. Repeated reads, lists, and existence checks on missing paths must not trigger any PPS HTTP requests
	for i := 0; i < 50; i++ {
		_, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ListOperation,
			Path:      fmt.Sprintf("Shared_Folders/missing_db_%d", i),
			Storage:   storage,
		})
		if err != logical.ErrUnsupportedPath {
			t.Fatalf("expected ErrUnsupportedPath on missing folder, got %v", err)
		}

		_, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      fmt.Sprintf("Shared_Folders/abb01p/missing_secret_%d", i),
			Storage:   storage,
		})
		if err != logical.ErrUnsupportedPath {
			t.Fatalf("expected ErrUnsupportedPath on missing secret, got %v", err)
		}
	}

	if got := atomic.LoadInt32(&mock.treeCalls); got != 1 {
		t.Errorf("expected full root treeCalls to remain 1, got %d", got)
	}
	if got := atomic.LoadInt32(&mock.groupCalls); got != 0 {
		t.Errorf("expected 0 partial group calls on cache misses, got %d", got)
	}
}

func TestFailedSubgroupRefreshKeepsCachedTreeWithoutFullTreeReload(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	p, err := b.Session(ctx, storage)
	if err != nil {
		t.Fatalf("failed getting session: %v", err)
	}
	if root := p.RequestRootCredentialGroup(false); root == nil {
		t.Fatalf("expected initial root tree")
	}
	if got := atomic.LoadInt32(&mock.treeCalls); got != 1 {
		t.Fatalf("expected 1 initial root tree fetch, got %d", got)
	}

	// Refreshing a non-existent subgroup ID returns 404 (freshGroup == nil) and must keep cached root without calling Invalidate()
	refreshed := p.RefreshGroup("non-existent-group-id")
	if refreshed == nil || refreshed.Id != "root-id" {
		t.Fatalf("expected cached root tree to be preserved, got %#v", refreshed)
	}
	if got := atomic.LoadInt32(&mock.treeCalls); got != 1 {
		t.Errorf("expected failed subgroup refresh not to fall back to full root tree reload (treeCalls=%d)", got)
	}
}

func TestCRUDRefreshesOnlyAffectedGroupInsteadOfFullTree(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	// Prime initial tree cache
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "Shared_Folders/abb01p",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("failed initial list: %v", err)
	}
	if got := atomic.LoadInt32(&mock.treeCalls); got != 1 {
		t.Fatalf("expected 1 initial root tree fetch, got %d", got)
	}

	// Perform Create, Update, and Delete inside Shared_Folders/abb01p
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "Shared_Folders/abb01p/TEMP_SECRET",
		Storage:   storage,
		Data: map[string]interface{}{
			"Username": "TEMP_USER",
			"Password": "temp-pass-1",
		},
	})
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "Shared_Folders/abb01p/TEMP_SECRET",
		Storage:   storage,
		Data: map[string]interface{}{
			"Notes": "updated note",
		},
	})
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "Shared_Folders/abb01p/TEMP_SECRET",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	if got := atomic.LoadInt32(&mock.treeCalls); got != 1 {
		t.Errorf("expected CRUD operations to use partial group sync without full root tree reloads (expected treeCalls=1, got %d)", got)
	}
	if got := atomic.LoadInt32(&mock.groupCalls); got < 3 {
		t.Errorf("expected at least 3 partial group sync calls for Create/Update/Delete, got %d", got)
	}
}

func TestPasswordRead404RefreshesParentGroupAndReturnsUnsupportedPath(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	// 1. Prime cache while ABBPRD_app (cred-1) exists
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "Shared_Folders/abb01p",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("failed initial list: %v", err)
	}

	// 2. Simulate DBA deleting cred-1 directly in PPS while it's still in Vault's cached tree
	mock.mu.Lock()
	deleteCredentialByID(&mock.root, "cred-1")
	delete(mock.passwords, "cred-1")
	mock.mu.Unlock()

	// 3. Reading Shared_Folders/abb01p/ABBPRD_app hits 404 on /password, refreshes grp-db1, and returns ErrUnsupportedPath
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
	})
	if err != logical.ErrUnsupportedPath {
		t.Fatalf("expected ErrUnsupportedPath when credential was deleted in PPS (404), got: %v", err)
	}
	if got := atomic.LoadInt32(&mock.treeCalls); got != 1 {
		t.Errorf("expected full root treeCalls to remain 1, got %d", got)
	}
	if got := atomic.LoadInt32(&mock.groupCalls); got != 1 {
		t.Errorf("expected 1 partial group refresh on 404, got %d", got)
	}

	// 4. Subsequent existence check or list immediately sees ABBPRD_app is gone without another HTTP fetch
	exists, err := b.pathExistenceCheck(ctx, &logical.Request{
		Path:    "Shared_Folders/abb01p/ABBPRD_app",
		Storage: storage,
	}, nil)
	if err != nil || exists {
		t.Errorf("expected ABBPRD_app to be evicted from cached group after 404 refresh, got exists=%v err=%v", exists, err)
	}
}

func TestConcurrentPasswordReadsRunInParallel(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	// Prime tree cache first
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "Shared_Folders/abb01p",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("failed initial list: %v", err)
	}

	mock.mu.Lock()
	mock.pwdDelay = 50 * time.Millisecond
	mock.mu.Unlock()

	const workers = 10
	start := time.Now()
	errCh := make(chan error, workers)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			resp, rErr := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "Shared_Folders/abb01p/ABBPRD_app",
				Storage:   storage,
			})
			if rErr != nil {
				errCh <- rErr
				return
			}
			if resp == nil || resp.Data["Password"] != "s3cret-abb01p" {
				errCh <- logical.ErrUnsupportedPath
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for rErr := range errCh {
		t.Fatalf("concurrent read failed: %v", rErr)
	}

	elapsed := time.Since(start)
	// Serialized execution of 10 * 50ms takes >= 500ms; parallel execution should complete well under 250ms.
	if elapsed >= 250*time.Millisecond {
		t.Fatalf("expected %d concurrent reads (50ms each) to run in parallel (< 250ms), took %v", workers, elapsed)
	}
}

func TestConcurrent401ReauthCoalescesTokenRefresh(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	mock.enforceToken = true
	b, storage := setupTestBackend(t, mock.server.URL)

	// Prime session and tree cache with mock-oauth-token-1
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "Shared_Folders/abb01p",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("failed initial list: %v", err)
	}

	// Rotate server token so all concurrent in-flight requests hit 401
	mock.mu.Lock()
	mock.token = "mock-oauth-token-2"
	mock.pwdDelay = 20 * time.Millisecond
	mock.mu.Unlock()

	const workers = 8
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			resp, rErr := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "Shared_Folders/abb01p/ABBPRD_app",
				Storage:   storage,
			})
			if rErr != nil || resp == nil || resp.Data["Password"] != "s3cret-abb01p" {
				errCh <- rErr
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for rErr := range errCh {
		t.Fatalf("concurrent 401 read failed: %v", rErr)
	}

	if got := atomic.LoadInt32(&mock.authCalls); got != 2 {
		t.Errorf("expected concurrent 401s to coalesce into 1 re-auth call (total authCalls=2), got %d", got)
	}
}

func TestResetSessionAndLogoutDoNotPanicOrBlock(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	// 1. Prime session and tree cache
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
	})
	if err != nil || resp == nil {
		t.Fatalf("initial read failed: %v", err)
	}

	p, err := b.Session(ctx, storage)
	if err != nil || p == nil {
		t.Fatalf("failed getting session: %v", err)
	}

	// 2. Invalidate config/access (triggers ResetSession -> Logout) and verify it doesn't panic or block
	start := time.Now()
	b.invalidate(ctx, "config/access")
	p.Logout() // second call must be safe/idempotent
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("expected Logout/ResetSession to return immediately (< 100ms), took %v", elapsed)
	}

	// 3. Subsequent read cleanly creates a new session
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.Data["Password"] != "s3cret-abb01p" {
		t.Fatalf("read after ResetSession failed: err=%v resp=%#v", err, resp)
	}
}

func TestReadCredentialMetadataOnlySkipsPasswordRequest(t *testing.T) {
	ctx := context.Background()
	mock := newMockPPSServer(t)
	b, storage := setupTestBackend(t, mock.server.URL)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "Shared_Folders/abb01p/ABBPRD_app",
		Storage:   storage,
		Data: map[string]interface{}{
			"metadata": "true",
		},
	})
	if err != nil || resp == nil {
		t.Fatalf("failed reading credential with metadata=true: err=%v resp=%#v", err, resp)
	}
	if resp.Data["Id"] != "cred-1" ||
		resp.Data["Name"] != "ABBPRD_app" ||
		resp.Data["Username"] != "ABBPRD" ||
		resp.Data["Url"] != "jdbc:oracle:thin:@abb01p:1521/ABBPRD" ||
		resp.Data["Custom:Env"] != "prod" {
		t.Fatalf("unexpected credential metadata: %#v", resp.Data)
	}
	if _, hasPassword := resp.Data["Password"]; hasPassword {
		t.Errorf("expected Password to be omitted when metadata=true, got %q", resp.Data["Password"])
	}
	if got := atomic.LoadInt32(&mock.pwdCalls); got != 0 {
		t.Errorf("expected 0 password HTTP requests when metadata=true, got %d", got)
	}
}

