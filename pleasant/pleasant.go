package pleasant

import (
	"github.com/hashicorp/vault/logical"
	"github.com/go-resty/resty"
	"strings"
	"time"
	"fmt"
	"sync"
	"sync/atomic"
)

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

func (p *Pleasant) Login(url, username, password string) *Pleasant {
	p.resty.SetHostURL(url).SetHeaders(map[string]string{
		"Content-Type": "application/json",
		"Accept": "application/json",
		"Accept-Encoding": "gzip",
	})

	p.auth.Store(p.RequestAuth(username, password))

	go func() {
		auth := p.auth.Load().(*AuthSuccess)
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
					p.auth.Store(p.RequestAuth(username, password))
					auth = p.auth.Load().(*AuthSuccess)
					duration = time.Duration(int(auth.ExpiresIn/2)) * time.Second
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

	return p
}

func (p *Pleasant) Logout() {
	p.reauth_quit <- true
	p.recredential_quit <- true
	p.root.Store(nil)
	p.auth.Store(nil)
}

func (p *Pleasant) GetAccessToken() string {
	return p.auth.Load().(*AuthSuccess).AccessToken
}

func (p *Pleasant) RequestAuth(username string, password string) *AuthSuccess {
	p.mutex.Lock()

	resp, _ := p.resty.R().SetFormData(map[string]string{
		"grant_type": "password",
		"username": username,
		"password": password,
	}).SetResult(AuthSuccess{}).Post("/OAuth2/Token")

	p.mutex.Unlock()

	return resp.Result().(*AuthSuccess)
}

func (p *Pleasant) Invalidate() *CredentialGroup {
	new_root := p.RequestCredentialGroup("")

	if new_root != nil {
		p.root.Store(new_root)
	}

	return new_root
}

func (p *Pleasant) RequestRootCredentialGroup(invalidate bool) *CredentialGroup {
	p.backend.Logger().Debug("RequestRootCredentialGroup")

	root := p.root.Load()

	if(root != nil && !invalidate) {
		p.backend.Logger().Debug("Return cached RootCredentialGroup")
		return root.(*CredentialGroup)
	}

	root = p.Invalidate()

	return root.(*CredentialGroup)
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

func (p *Pleasant) Read(path string) (*CredentialGroup, *Credential) {
	b := p.backend

	b.Logger().Debug("Read", path)
	path_splitted := delete_empty(strings.Split(path, "/"))
	path_rest := path_splitted

	b.Logger().Debug("PathSplitted", fmt.Sprintf("%v", path_splitted))

	p.mutex.Lock()
	node := p.RequestRootCredentialGroup(false)
	p.mutex.Unlock()

	if(len(path_splitted) == 0) {
		return node, nil
	}

	for _, name := range path_splitted[:len(path_splitted) - 1] {
		b.Logger().Debug("Iterate", name)
		b.Logger().Debug("PathRest", fmt.Sprintf("%v", path_rest))

		for _, group := range node.Children {

			if(name == group.Name || name == group.Name + "[" + group.Id + "]") {
				b.Logger().Debug("Found group", group.Name)
				node = &group
				break
			}
		}

		if (name != node.Name && name != node.Name + "[" + node.Id + "]") {
			b.Logger().Debug("Group not found", name)
			break
		}

		path_rest = path_rest[1:]
	}

	last_leaf := path_rest[0]
	b.Logger().Debug("LastLeaf", last_leaf)

	for _, credential := range node.Credentials {
		b.Logger().Debug("LastLeaf check credential", credential.Name)

		if credential.Name == last_leaf || credential.Name+"["+credential.Id+"]" == last_leaf {
			b.Logger().Debug("LastLeaf is Credential", credential.Name)
			return node, &credential
		}
	}

	for _, credential := range node.Credentials {
		b.Logger().Debug("LastLeaf check credential", credential.Name)

		if credential.Username == last_leaf || credential.Username+"["+credential.Id+"]" == last_leaf {
			b.Logger().Debug("LastLeaf is Credential", credential.Name)
			return node, &credential
		}
	}

	for _, group := range node.Children {
		b.Logger().Debug("LastLeaf check group", group.Name)

		if (group.Name == last_leaf || group.Name + "[" + group.Id + "]" == last_leaf) {
			b.Logger().Debug("LastLeaf is CredentialGroup", group.Name)
			return &group, nil
		}
	}

	b.Logger().Debug("LastLeaf not found", last_leaf)
	return nil, nil
}

func (p *Pleasant) RequestCredentialGroup(id string) *CredentialGroup {
	request := p.resty.R().SetHeader("Authorization", p.GetAccessToken()).SetResult(CredentialGroup{})
	resp, _ := request.Get(strings.Join([]string {"/api/v4/rest/credentialgroup/", id}, "/"))

	var result *CredentialGroup = nil

	if resp.StatusCode() == 200 && resp.Result() != nil {
		result = resp.Result().(*CredentialGroup)
	}

	return result
}

func (p *Pleasant) RequestCredential(id string) *Credential {
	p.mutex.Lock()

	request := p.resty.R().SetHeader("Authorization", p.GetAccessToken()).SetResult(Credential{})
	resp, _ := request.Get(strings.Join([]string {"/api/v4/rest/credential/", id}, "/"))

	var result *Credential = nil

	if resp.StatusCode() == 200 && resp.Result() != nil {
		result = resp.Result().(*Credential)
	}

	p.mutex.Unlock()

	return result
}

func (p *Pleasant) UpdateCredential(credential *Credential)  {
	p.mutex.Lock()
	request := p.resty.R().SetHeader("Authorization", p.GetAccessToken()).SetBody(credential)
	request.Put(strings.Join([]string {"/api/v4/rest/credential/", credential.Id}, "/"))
	p.Invalidate()
	p.mutex.Unlock()
}

func (p *Pleasant) UpdateCredentialGroup(group *CredentialGroup)  {
	p.mutex.Lock()
	request := p.resty.R().SetHeader("Authorization", p.GetAccessToken()).SetBody(group)
	request.Put(strings.Join([]string {"/api/v4/rest/credentialgroup/", group.Id}, "/"))
	p.Invalidate()
	p.mutex.Unlock()
}

func (p *Pleasant) CreateCredential(credential *Credential)  {
	p.mutex.Lock()
	request := p.resty.R().SetHeader("Authorization", p.GetAccessToken()).SetBody(credential)
	request.Post("/api/v4/rest/credential")
	p.Invalidate()
	p.mutex.Unlock()
}

func (p *Pleasant) CreateCredentialGroup(group *CredentialGroup)  {
	p.mutex.Lock()
	request := p.resty.R().SetHeader("Authorization", p.GetAccessToken()).SetBody(group)
	request.Post("/api/v4/rest/credentialgroup")
	p.Invalidate()
	p.mutex.Unlock()
}

func (p *Pleasant) DeleteCredential(credential *Credential)  {
	p.mutex.Lock()
	request := p.resty.R().SetHeader("Authorization", p.GetAccessToken())
	request.Delete(strings.Join([]string {"/api/v4/rest/credential/", credential.Id}, "/"))
	p.Invalidate()
	p.mutex.Unlock()
}

func (p *Pleasant) DeleteCredentialGroup(group *CredentialGroup)  {
	p.mutex.Lock()
	request := p.resty.R().SetHeader("Authorization", p.GetAccessToken())
	request.Delete(strings.Join([]string {"/api/v4/rest/credentialgroup/", group.Id}, "/"))
	p.Invalidate()
	p.mutex.Unlock()
}

func (p *Pleasant) RequestCredentialPassword(id string) string {
	p.mutex.Lock()
	request := p.resty.R().SetHeader("Authorization", p.GetAccessToken())
	resp, _ := request.Get(strings.Join([]string {"/api/v4/rest/credential/", id, "password"}, "/"))
	p.mutex.Unlock()

	if(len(resp.String()) > 0) {
		return (resp.String())[1 : len(resp.String())-1]
	}

	return ""
}
