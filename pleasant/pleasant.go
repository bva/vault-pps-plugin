package pleasant

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/resty.v1"
)

var ErrCredentialNotFound = errors.New("PPS credential not found")

type AuthSuccess struct {
	AccessToken string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn uint `json:"expires_in"`
}

type CommentPrompt struct {
	AskForCommentOnViewPassword bool `json:"AskForCommentOnViewPassword"`
	AskForCommentOnViewOffline bool `json:"AskForCommentOnViewOffline"`
	AskForCommentOnModifyEntries bool `json:"AskForCommentOnModifyEntries"`
	AskForCommentOnMoveEntries bool `json:"AskForCommentOnMoveEntries"`
	AskForCommentOnMoveFolders bool `json:"AskForCommentOnMoveFolders"`
	AskForCommentOnModifyFolders bool `json:"AskForCommentOnModifyFolders"`
}

type Attachment struct {
	CredentialObjectId string `json:"CredentialObjectId"`
	FileName string `json:"FileName"`
	FileData string `json:"FileData"`
}

type Tag struct {
	Name string `json:"Name"`
}

type Credential struct {
	Id string `json:"Id"`
	Name string `json:"Name"`
	Password string `json:"Password"`
	Username string `json:"Username,omitempty"`
	Url string `json:"Url,omitempty"`
	Notes string `json:",omitempty"`
	GroupId string `json:"GroupId"`
	Created string `json:"Created"`
	Modified string `json:"Modified"`
	Expires string `json:",omitempty"`
	CustomUserFields map[string]string `json:",omitempty"`
	CustomApplicationFields map[string]string `json:",omitempty"`
	Attachments []Attachment `json:",omitempty"`
	UsageComment string `json:"UsageComment"`
	Tags []Tag `json:",omitempty"`
	HasModifyEntriesAccess bool `json:"HasModifyEntriesAccess"`
	HasViewEntryContentsAccess bool `json:"HasViewEntryContentsAccess"`
	CommentPrompts CommentPrompt `json:"CommentPrompts"`
}

type CredentialGroup struct {
	Id string `json:"Id"`
	Name string `json:"Name"`
	ParentId string `json:"ParentId"`
	Notes string `json:",omitempty"`
	Created string `json:",omitempty"`
	Modified string `json:",omitempty"`
	Expires string `json:",omitempty"`
	CustomUserFields map[string]string `json:",omitempty"`
	CustomApplicationFields map[string]string `json:",omitempty"`
	Attachments []Attachment `json:",omitempty"`

	Children []CredentialGroup
	Credentials []Credential
	Tags []Tag `json:",omitempty"`
	UsageComment string `json:"UsageComment"`

	HasModifyEntriesAccess bool `json:"HasModifyEntriesAccess"`
	HasViewEntryContentsAccess bool `json:"HasViewEntryContentsAccess"`
}

type Pleasant struct {
	resty *resty.Client

	username string
	password string

	auth atomic.Value
	root atomic.Value

	backend logical.Backend

	authMu sync.Mutex
	treeMu sync.Mutex
	httpMu sync.Mutex

	treeTTL          time.Duration
	missCooldown     time.Duration
	httpTimeout      time.Duration
	invalidateOnMiss bool
	parallelRequests bool
	lastMissRefresh  map[string]time.Time

	stopCh   chan struct{}
	stopOnce sync.Once
}

const (
	defaultTreeTTL      = defaultTreeTTLSeconds * time.Second
	defaultMissCooldown = defaultMissCooldownSeconds * time.Second
	defaultHTTPTimeout  = defaultHTTPTimeoutSeconds * time.Second
)

func NewPleasant(backend logical.Backend) *Pleasant {
	p := new(Pleasant)

	p.stopCh = make(chan struct{})
	p.treeTTL = defaultTreeTTL
	p.missCooldown = defaultMissCooldown
	p.httpTimeout = defaultHTTPTimeout
	p.lastMissRefresh = make(map[string]time.Time)

	p.backend = backend
	p.resty = resty.New().SetTimeout(p.httpTimeout)

	return p
}

func (p *Pleasant) Login(url, username, password string) error {
	p.username = username
	p.password = password

	if p.httpTimeout > 0 {
		p.resty.SetTimeout(p.httpTimeout)
	}
	p.resty.SetHostURL(url).SetHeaders(map[string]string{
		"Content-Type":    "application/json",
		"Accept":          "application/json",
		"Accept-Encoding": "gzip",
	})

	initialAuth, err := p.requestAuth(username, password)
	if err != nil {
		return err
	}
	p.auth.Store(initialAuth)

	go func() {
		auth := initialAuth
		retrySec := int(auth.ExpiresIn / 2)
		if retrySec <= 0 {
			retrySec = 10
		}
		timer := time.NewTimer(time.Duration(retrySec) * time.Second)
		defer timer.Stop()

		for {
			select {
			case <-p.stopCh:
				p.backend.Logger().Debug("Timer cached AuthToken cancelled")
				return

			case <-timer.C:
				p.backend.Logger().Debug("Timer cached AuthToken")
				if refreshed, err := p.refreshAuthToken(""); err == nil {
					auth = refreshed
				} else {
					p.backend.Logger().Warn("Failed to refresh Pleasant AuthToken, keeping previous token", "error", err)
				}
				nextSec := int(auth.ExpiresIn / 2)
				if nextSec <= 0 {
					nextSec = 10
				}
				timer.Reset(time.Duration(nextSec) * time.Second)
			}
		}
	}()

	go func() {
		p.backend.Logger().Debug("Starting cached RootCredentialGroup goroutine")

		treeTTL := p.treeTTL
		if treeTTL <= 0 {
			treeTTL = defaultTreeTTL
		}
		ticker := time.NewTicker(treeTTL)
		defer ticker.Stop()

		for {
			select {
			case <-p.stopCh:
				p.backend.Logger().Debug("Timer cached RootCredentialGroup cancelled")
				return

			case <-ticker.C:
				p.backend.Logger().Debug("Timer cached RootCredentialGroup")
				p.treeMu.Lock()
				p.Invalidate()
				p.treeMu.Unlock()
			}
		}
	}()

	return nil
}

func (p *Pleasant) Logout() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})
	p.root.Store((*CredentialGroup)(nil))
	p.auth.Store((*AuthSuccess)(nil))
}

func (p *Pleasant) GetAccessToken() string {
	raw := p.auth.Load()
	if raw == nil {
		return ""
	}
	auth, ok := raw.(*AuthSuccess)
	if !ok || auth == nil {
		return ""
	}
	return auth.AccessToken
}

func (p *Pleasant) doHTTP(fn func() (*resty.Response, error)) (*resty.Response, error) {
	if !p.parallelRequests {
		p.httpMu.Lock()
		defer p.httpMu.Unlock()
	}
	return fn()
}

func (p *Pleasant) requestAuth(username string, password string) (*AuthSuccess, error) {
	resp, err := p.doHTTP(func() (*resty.Response, error) {
		return p.resty.R().SetFormData(map[string]string{
			"grant_type": "password",
			"username":   username,
			"password":   password,
		}).SetResult(AuthSuccess{}).Post("/OAuth2/Token")
	})

	if err != nil {
		return nil, err
	}
	if resp == nil || resp.StatusCode() != http.StatusOK {
		status := 0
		body := ""
		if resp != nil {
			status = resp.StatusCode()
			body = resp.String()
		}
		return nil, fmt.Errorf("PPS OAuth2 token request failed with status %d: %s", status, body)
	}

	auth, ok := resp.Result().(*AuthSuccess)
	if !ok || auth == nil || auth.AccessToken == "" {
		return nil, fmt.Errorf("PPS OAuth2 token response missing access_token")
	}

	return auth, nil
}

func (p *Pleasant) refreshAuthToken(failedToken string) (*AuthSuccess, error) {
	p.authMu.Lock()
	defer p.authMu.Unlock()

	if failedToken != "" {
		if current := p.GetAccessToken(); current != "" && current != failedToken {
			if raw := p.auth.Load(); raw != nil {
				if auth, ok := raw.(*AuthSuccess); ok && auth != nil {
					return auth, nil
				}
			}
		}
	}

	refreshed, err := p.requestAuth(p.username, p.password)
	if err != nil {
		return nil, err
	}
	p.auth.Store(refreshed)
	return refreshed, nil
}

func (p *Pleasant) RequestAuth(username string, password string) *AuthSuccess {
	auth, err := p.requestAuth(username, password)
	if err != nil {
		return &AuthSuccess{}
	}
	return auth
}

func (p *Pleasant) executeWithAuthRetry(doReq func(token string) (*resty.Response, error)) (*resty.Response, error) {
	var usedToken string
	resp, err := p.doHTTP(func() (*resty.Response, error) {
		usedToken = p.GetAccessToken()
		return doReq(usedToken)
	})
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.StatusCode() == http.StatusUnauthorized {
		refreshed, authErr := p.refreshAuthToken(usedToken)
		if authErr != nil {
			return resp, fmt.Errorf("PPS re-authentication after 401 failed: %w", authErr)
		}
		return p.doHTTP(func() (*resty.Response, error) {
			return doReq(refreshed.AccessToken)
		})
	}
	return resp, nil
}

func (p *Pleasant) Invalidate() *CredentialGroup {
	new_root := p.RequestCredentialGroup("")

	if new_root != nil {
		p.root.Store(new_root)
		p.lastMissRefresh = make(map[string]time.Time)
	}

	return new_root
}

func replaceGroupInTree(node *CredentialGroup, target *CredentialGroup) (*CredentialGroup, bool) {
	if node == nil || target == nil {
		return nil, false
	}
	if node.Id == target.Id {
		cloned := *target
		return &cloned, true
	}
	for i := range node.Children {
		if updatedChild, ok := replaceGroupInTree(&node.Children[i], target); ok {
			cloned := *node
			children := make([]CredentialGroup, len(node.Children))
			copy(children, node.Children)
			children[i] = *updatedChild
			cloned.Children = children
			return &cloned, true
		}
	}
	return node, false
}

func (p *Pleasant) RefreshCredentialGroup(groupId string) *CredentialGroup {
	if groupId == "" {
		return p.Invalidate()
	}

	raw := p.root.Load()
	if raw == nil {
		return p.Invalidate()
	}
	curRoot, ok := raw.(*CredentialGroup)
	if !ok || curRoot == nil || curRoot.Id == groupId {
		return p.Invalidate()
	}

	freshGroup := p.RequestCredentialGroup(groupId)
	if freshGroup == nil {
		return curRoot
	}

	if updatedRoot, replaced := replaceGroupInTree(curRoot, freshGroup); replaced {
		p.root.Store(updatedRoot)
		return updatedRoot
	}

	return curRoot
}

func (p *Pleasant) getCachedRoot() *CredentialGroup {
	if raw := p.root.Load(); raw != nil {
		if cg, ok := raw.(*CredentialGroup); ok && cg != nil {
			return cg
		}
	}
	return nil
}

func (p *Pleasant) RefreshGroup(groupId string) *CredentialGroup {
	p.treeMu.Lock()
	defer p.treeMu.Unlock()
	return p.RefreshCredentialGroup(groupId)
}

func (p *Pleasant) RequestRootCredentialGroup(invalidate bool) *CredentialGroup {
	p.backend.Logger().Debug("RequestRootCredentialGroup")

	if !invalidate {
		if cg := p.getCachedRoot(); cg != nil {
			p.backend.Logger().Debug("Return cached RootCredentialGroup")
			return cg
		}
	}

	p.treeMu.Lock()
	defer p.treeMu.Unlock()

	if !invalidate {
		if cg := p.getCachedRoot(); cg != nil {
			p.backend.Logger().Debug("Return cached RootCredentialGroup")
			return cg
		}
	}

	return p.Invalidate()
}

func delete_empty (s []string) []string {
	var r []string

	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}

	return r
}

func (p *Pleasant) readFromTree(root *CredentialGroup, path_splitted []string) (*CredentialGroup, *Credential, *CredentialGroup) {
	b := p.backend

	if root == nil {
		return nil, nil, nil
	}

	if len(path_splitted) == 0 {
		return root, nil, root
	}

	node := root
	path_rest := path_splitted

	for _, name := range path_splitted[:len(path_splitted)-1] {
		b.Logger().Debug("Iterate", name)

		found := false
		for i := range node.Children {
			group := &node.Children[i]
			if name == group.Name || name == group.Name+"["+group.Id+"]" {
				b.Logger().Debug("Found group", group.Name)
				node = group
				found = true
				break
			}
		}

		if !found {
			b.Logger().Debug("Group not found", name)
			return nil, nil, node
		}

		path_rest = path_rest[1:]
	}

	last_leaf := path_rest[0]
	b.Logger().Debug("LastLeaf", last_leaf)

	for i := range node.Credentials {
		credential := &node.Credentials[i]
		if credential.Name == last_leaf || credential.Name+"["+credential.Id+"]" == last_leaf {
			b.Logger().Debug("LastLeaf is Credential", credential.Name)
			matched := *credential
			return node, &matched, node
		}
	}

	for i := range node.Credentials {
		credential := &node.Credentials[i]
		if credential.Username == last_leaf || credential.Username+"["+credential.Id+"]" == last_leaf {
			b.Logger().Debug("LastLeaf is Credential", credential.Name)
			matched := *credential
			return node, &matched, node
		}
	}

	for i := range node.Children {
		group := &node.Children[i]
		if group.Name == last_leaf || group.Name+"["+group.Id+"]" == last_leaf {
			b.Logger().Debug("LastLeaf is CredentialGroup", group.Name)
			matched := *group
			return &matched, nil, &matched
		}
	}

	b.Logger().Debug("LastLeaf not found", last_leaf)
	return nil, nil, node
}

func (p *Pleasant) Read(path string) (*CredentialGroup, *Credential) {
	b := p.backend

	b.Logger().Debug("Read", path)
	path_splitted := delete_empty(strings.Split(path, "/"))

	root := p.RequestRootCredentialGroup(false)
	if root == nil {
		return nil, nil
	}

	group, credential, lastMatchedGroup := p.readFromTree(root, path_splitted)
	if group != nil || credential != nil || !p.invalidateOnMiss {
		return group, credential
	}

	refreshId := ""
	if lastMatchedGroup != nil {
		refreshId = lastMatchedGroup.Id
	}

	p.treeMu.Lock()
	if currentRoot := p.getCachedRoot(); currentRoot != nil && currentRoot != root {
		if g, c, _ := p.readFromTree(currentRoot, path_splitted); g != nil || c != nil {
			p.treeMu.Unlock()
			return g, c
		}
	}
	if p.missCooldown > 0 && time.Since(p.lastMissRefresh[refreshId]) < p.missCooldown {
		p.treeMu.Unlock()
		return nil, nil
	}
	refreshedRoot := p.RefreshCredentialGroup(refreshId)
	p.lastMissRefresh[refreshId] = time.Now()
	p.treeMu.Unlock()

	group, credential, _ = p.readFromTree(refreshedRoot, path_splitted)
	return group, credential
}

func (p *Pleasant) RequestCredentialGroup(id string) *CredentialGroup {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		request := p.resty.R().SetHeader("Authorization", token).SetResult(CredentialGroup{})
		return request.Get(strings.Join([]string{"/api/v4/rest/credentialgroup", id}, "/"))
	})
	if err != nil || resp == nil {
		return nil
	}

	if resp.StatusCode() == http.StatusOK && resp.Result() != nil {
		if result, ok := resp.Result().(*CredentialGroup); ok {
			return result
		}
	}

	return nil
}

func (p *Pleasant) RequestCredential(id string) *Credential {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		request := p.resty.R().SetHeader("Authorization", token).SetResult(Credential{})
		return request.Get(strings.Join([]string{"/api/v4/rest/credential/", id}, "/"))
	})
	if err != nil || resp == nil {
		return nil
	}

	if resp.StatusCode() == http.StatusOK && resp.Result() != nil {
		if result, ok := resp.Result().(*Credential); ok {
			return result
		}
	}

	return nil
}

func isEntryOrGroupNotFound(resp *resty.Response) bool {
	if resp == nil {
		return false
	}
	code := resp.StatusCode()
	if code == http.StatusNotFound {
		return true
	}
	if code == http.StatusBadRequest {
		status := strings.ToLower(resp.Status())
		body := strings.ToLower(strings.TrimSpace(resp.String()))
		if strings.Contains(status, "cannot find") || strings.Contains(body, "cannot find") || body == "" {
			return true
		}
	}
	return false
}

func checkWriteResponse(op string, resp *resty.Response, err error) error {
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("PPS %s returned nil response", op)
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return fmt.Errorf("PPS %s failed with status %d: %s", op, resp.StatusCode(), resp.String())
	}
	return nil
}

func (p *Pleasant) UpdateCredential(credential *Credential) error {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		request := p.resty.R().SetHeader("Authorization", token).SetBody(credential)
		return request.Put(strings.Join([]string{"/api/v4/rest/credential/", credential.Id}, "/"))
	})
	if err := checkWriteResponse("UpdateCredential", resp, err); err != nil {
		if isEntryOrGroupNotFound(resp) {
			p.RefreshGroup(credential.GroupId)
		}
		return err
	}
	p.RefreshGroup(credential.GroupId)
	return nil
}

func (p *Pleasant) UpdateCredentialGroup(group *CredentialGroup) error {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		request := p.resty.R().SetHeader("Authorization", token).SetBody(group)
		return request.Put(strings.Join([]string{"/api/v4/rest/credentialgroup/", group.Id}, "/"))
	})
	if err := checkWriteResponse("UpdateCredentialGroup", resp, err); err != nil {
		if isEntryOrGroupNotFound(resp) {
			p.RefreshGroup(group.ParentId)
		}
		return err
	}
	p.RefreshGroup(group.Id)
	return nil
}

func (p *Pleasant) CreateCredential(credential *Credential) error {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		request := p.resty.R().SetHeader("Authorization", token).SetBody(credential)
		return request.Post("/api/v4/rest/credential")
	})
	if err := checkWriteResponse("CreateCredential", resp, err); err != nil {
		return err
	}
	p.RefreshGroup(credential.GroupId)
	return nil
}

func (p *Pleasant) CreateCredentialGroup(group *CredentialGroup) error {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		request := p.resty.R().SetHeader("Authorization", token).SetBody(group)
		return request.Post("/api/v4/rest/credentialgroup")
	})
	if err := checkWriteResponse("CreateCredentialGroup", resp, err); err != nil {
		return err
	}
	p.RefreshGroup(group.ParentId)
	return nil
}

func (p *Pleasant) DeleteCredential(credential *Credential) error {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		request := p.resty.R().SetHeader("Authorization", token)
		return request.Delete(strings.Join([]string{"/api/v4/rest/credential/", credential.Id}, "/"))
	})
	if err := checkWriteResponse("DeleteCredential", resp, err); err != nil {
		if isEntryOrGroupNotFound(resp) {
			p.RefreshGroup(credential.GroupId)
		}
		return err
	}
	p.RefreshGroup(credential.GroupId)
	return nil
}

func (p *Pleasant) DeleteCredentialGroup(group *CredentialGroup) error {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		request := p.resty.R().SetHeader("Authorization", token)
		return request.Delete(strings.Join([]string{"/api/v4/rest/credentialgroup/", group.Id}, "/"))
	})
	if err := checkWriteResponse("DeleteCredentialGroup", resp, err); err != nil {
		if isEntryOrGroupNotFound(resp) {
			p.RefreshGroup(group.ParentId)
		}
		return err
	}
	p.RefreshGroup(group.ParentId)
	return nil
}

func (p *Pleasant) RequestCredentialPassword(id string) (string, error) {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		request := p.resty.R().SetHeader("Authorization", token)
		return request.Get(strings.Join([]string{"/api/v4/rest/credential/", id, "password"}, "/"))
	})
	if err != nil {
		return "", err
	}
	if isEntryOrGroupNotFound(resp) {
		return "", fmt.Errorf("%w: %s", ErrCredentialNotFound, id)
	}
	if resp == nil || resp.StatusCode() != http.StatusOK {
		status := 0
		body := ""
		if resp != nil {
			status = resp.StatusCode()
			body = resp.String()
		}
		return "", fmt.Errorf("PPS password request failed with status %d: %s", status, body)
	}

	var password string
	if err := json.Unmarshal(resp.Body(), &password); err != nil {
		return "", fmt.Errorf("failed to decode PPS password response: %w", err)
	}

	return password, nil
}
