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

	mutex *sync.Mutex

	reauth_quit chan bool
	recredential_quit chan bool
}

func NewPleasant(backend logical.Backend) *Pleasant {
	p := new(Pleasant)

	p.mutex = &sync.Mutex{}

	p.reauth_quit = make(chan bool)
	p.recredential_quit = make(chan bool)

	p.backend = backend
	p.resty = resty.New()

	return p
}

func (p *Pleasant) Login(url, username, password string) error {
	p.username = username
	p.password = password

	p.resty.SetHostURL(url).SetHeaders(map[string]string{
		"Content-Type": "application/json",
		"Accept": "application/json",
		"Accept-Encoding": "gzip",
	})

	initialAuth, err := p.requestAuth(username, password)
	if err != nil {
		return err
	}
	p.auth.Store(initialAuth)

	go func() {
		auth := initialAuth
		ticker := time.NewTicker(time.Second)

		duration := time.Duration(int(auth.ExpiresIn/2)) * time.Second

		for range ticker.C {
			duration -= time.Second

			select {
			case <- p.reauth_quit:
				p.backend.Logger().Debug("Timer cached AuthToken cancelled")
				return

			default:
				if duration <= 0 {
					p.backend.Logger().Debug("Timer cached AuthToken")
					if refreshed, err := p.requestAuth(username, password); err == nil {
						p.auth.Store(refreshed)
						auth = refreshed
					} else {
						p.backend.Logger().Warn("Failed to refresh Pleasant AuthToken, keeping previous token", "error", err)
					}
					retrySec := int(auth.ExpiresIn / 2)
					if retrySec <= 0 {
						retrySec = 10
					}
					duration = time.Duration(retrySec) * time.Second
				}
			}
		}
	}()

	go func() {
		p.backend.Logger().Debug("Starting cached RootCredentialGroup goroutine")

		ticker := time.NewTicker(time.Second)
		duration := time.Duration(5*60) * time.Second

		for range ticker.C {
			duration -= time.Second

			select {
			case <- p.recredential_quit:
				p.backend.Logger().Debug("Timer cached RootCredentialGroup cancelled")
				return

			default:
				if duration <= 0 {
					p.backend.Logger().Debug("Timer cached RootCredentialGroup")
					p.mutex.Lock()
					p.Invalidate()
					p.mutex.Unlock()
					duration = time.Duration(5*60) * time.Second
				}
			}
		}
	}()

	return nil
}

func (p *Pleasant) Logout() {
	p.reauth_quit <- true
	p.recredential_quit <- true
	p.root.Store(nil)
	p.auth.Store(nil)
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

func (p *Pleasant) requestAuth(username string, password string) (*AuthSuccess, error) {
	p.mutex.Lock()
	resp, err := p.resty.R().SetFormData(map[string]string{
		"grant_type": "password",
		"username":   username,
		"password":   password,
	}).SetResult(AuthSuccess{}).Post("/OAuth2/Token")
	p.mutex.Unlock()

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

func (p *Pleasant) RequestAuth(username string, password string) *AuthSuccess {
	auth, err := p.requestAuth(username, password)
	if err != nil {
		return &AuthSuccess{}
	}
	return auth
}

func (p *Pleasant) executeWithAuthRetry(doReq func(token string) (*resty.Response, error)) (*resty.Response, error) {
	resp, err := doReq(p.GetAccessToken())
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.StatusCode() == http.StatusUnauthorized {
		refreshed, authErr := p.requestAuth(p.username, p.password)
		if authErr != nil {
			return resp, fmt.Errorf("PPS re-authentication after 401 failed: %w", authErr)
		}
		p.auth.Store(refreshed)
		return doReq(refreshed.AccessToken)
	}
	return resp, nil
}

func (p *Pleasant) Invalidate() *CredentialGroup {
	new_root := p.RequestCredentialGroup("")

	if new_root != nil {
		p.root.Store(new_root)
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
		return p.Invalidate()
	}

	if updatedRoot, replaced := replaceGroupInTree(curRoot, freshGroup); replaced {
		p.root.Store(updatedRoot)
		return updatedRoot
	}

	return p.Invalidate()
}

func (p *Pleasant) RefreshGroup(groupId string) *CredentialGroup {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.RefreshCredentialGroup(groupId)
}

func (p *Pleasant) RequestRootCredentialGroup(invalidate bool) *CredentialGroup {
	p.backend.Logger().Debug("RequestRootCredentialGroup")

	root := p.root.Load()

	if root != nil && !invalidate {
		if cg, ok := root.(*CredentialGroup); ok && cg != nil {
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
		b.Logger().Debug("PathRest", fmt.Sprintf("%v", path_rest))

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
		credential := node.Credentials[i]
		b.Logger().Debug("LastLeaf check credential", credential.Name)

		if credential.Name == last_leaf || credential.Name+"["+credential.Id+"]" == last_leaf {
			b.Logger().Debug("LastLeaf is Credential", credential.Name)
			return node, &credential, node
		}
	}

	for i := range node.Credentials {
		credential := node.Credentials[i]
		b.Logger().Debug("LastLeaf check credential", credential.Name)

		if credential.Username == last_leaf || credential.Username+"["+credential.Id+"]" == last_leaf {
			b.Logger().Debug("LastLeaf is Credential", credential.Name)
			return node, &credential, node
		}
	}

	for i := range node.Children {
		group := node.Children[i]
		b.Logger().Debug("LastLeaf check group", group.Name)

		if group.Name == last_leaf || group.Name+"["+group.Id+"]" == last_leaf {
			b.Logger().Debug("LastLeaf is CredentialGroup", group.Name)
			return &group, nil, &group
		}
	}

	b.Logger().Debug("LastLeaf not found", last_leaf)
	return nil, nil, node
}

func (p *Pleasant) Read(path string) (*CredentialGroup, *Credential) {
	b := p.backend

	b.Logger().Debug("Read", path)
	path_splitted := delete_empty(strings.Split(path, "/"))

	b.Logger().Debug("PathSplitted", fmt.Sprintf("%v", path_splitted))

	p.mutex.Lock()
	root := p.RequestRootCredentialGroup(false)
	p.mutex.Unlock()

	if root == nil {
		return nil, nil
	}

	group, credential, lastMatchedGroup := p.readFromTree(root, path_splitted)
	if group != nil || credential != nil {
		return group, credential
	}

	refreshId := ""
	if lastMatchedGroup != nil {
		refreshId = lastMatchedGroup.Id
	}

	p.mutex.Lock()
	refreshedRoot := p.RefreshCredentialGroup(refreshId)
	p.mutex.Unlock()

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
		p.mutex.Lock()
		defer p.mutex.Unlock()

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
		p.mutex.Lock()
		defer p.mutex.Unlock()

		request := p.resty.R().SetHeader("Authorization", token).SetBody(credential)
		return request.Put(strings.Join([]string{"/api/v4/rest/credential/", credential.Id}, "/"))
	})
	if err := checkWriteResponse("UpdateCredential", resp, err); err != nil {
		if resp != nil && resp.StatusCode() == http.StatusNotFound {
			p.RefreshGroup(credential.GroupId)
		}
		return err
	}
	p.RefreshGroup(credential.GroupId)
	return nil
}

func (p *Pleasant) UpdateCredentialGroup(group *CredentialGroup) error {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		p.mutex.Lock()
		defer p.mutex.Unlock()

		request := p.resty.R().SetHeader("Authorization", token).SetBody(group)
		return request.Put(strings.Join([]string{"/api/v4/rest/credentialgroup/", group.Id}, "/"))
	})
	if err := checkWriteResponse("UpdateCredentialGroup", resp, err); err != nil {
		if resp != nil && resp.StatusCode() == http.StatusNotFound {
			p.RefreshGroup(group.ParentId)
		}
		return err
	}
	p.RefreshGroup(group.Id)
	return nil
}

func (p *Pleasant) CreateCredential(credential *Credential) error {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		p.mutex.Lock()
		defer p.mutex.Unlock()

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
		p.mutex.Lock()
		defer p.mutex.Unlock()

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
		p.mutex.Lock()
		defer p.mutex.Unlock()

		request := p.resty.R().SetHeader("Authorization", token)
		return request.Delete(strings.Join([]string{"/api/v4/rest/credential/", credential.Id}, "/"))
	})
	if err := checkWriteResponse("DeleteCredential", resp, err); err != nil {
		if resp != nil && resp.StatusCode() == http.StatusNotFound {
			p.RefreshGroup(credential.GroupId)
		}
		return err
	}
	p.RefreshGroup(credential.GroupId)
	return nil
}

func (p *Pleasant) DeleteCredentialGroup(group *CredentialGroup) error {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		p.mutex.Lock()
		defer p.mutex.Unlock()

		request := p.resty.R().SetHeader("Authorization", token)
		return request.Delete(strings.Join([]string{"/api/v4/rest/credentialgroup/", group.Id}, "/"))
	})
	if err := checkWriteResponse("DeleteCredentialGroup", resp, err); err != nil {
		if resp != nil && resp.StatusCode() == http.StatusNotFound {
			p.RefreshGroup(group.ParentId)
		}
		return err
	}
	p.RefreshGroup(group.ParentId)
	return nil
}

func (p *Pleasant) RequestCredentialPassword(id string) (string, error) {
	resp, err := p.executeWithAuthRetry(func(token string) (*resty.Response, error) {
		p.mutex.Lock()
		defer p.mutex.Unlock()

		request := p.resty.R().SetHeader("Authorization", token)
		return request.Get(strings.Join([]string{"/api/v4/rest/credential/", id, "password"}, "/"))
	})
	if err != nil {
		return "", err
	}
	if resp != nil && resp.StatusCode() == http.StatusNotFound {
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
