package pleasant

import (
	"context"
	"strings"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// kvPaths is used to test CRUD and List operations. It is a simplified
// version of the passthrough backend that only accepts string values.
func kvPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: ".*",
			Fields: map[string]*framework.FieldSchema{
				"id":     &framework.FieldSchema{Type: framework.TypeString},
				"name":     &framework.FieldSchema{Type: framework.TypeString},
				"group":     &framework.FieldSchema{Type: framework.TypeBool},
				"user_name":     &framework.FieldSchema{Type: framework.TypeString},
				"password":  &framework.FieldSchema{Type: framework.TypeString},
				"notes":     &framework.FieldSchema{Type: framework.TypeString},
				"url":   &framework.FieldSchema{Type: framework.TypeString},
				"value":   &framework.FieldSchema{Type: framework.TypeKVPairs},
				"created":   &framework.FieldSchema{Type: framework.TypeString},
				"modified":  &framework.FieldSchema{Type: framework.TypeString},
				"expires":   &framework.FieldSchema{Type: framework.TypeString},
				"custom_fields":   &framework.FieldSchema{Type: framework.TypeKVPairs},
				"attachments":   &framework.FieldSchema{Type: framework.TypeKVPairs},
			},
			ExistenceCheck: b.pathExistenceCheck,

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathKVRead,
				logical.CreateOperation: b.pathKVCreate,
				logical.UpdateOperation: b.pathKVUpdate,
				logical.DeleteOperation: b.pathKVDelete,
				logical.ListOperation: b.pathKVList,
			},
		},
	}
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	b.Logger().Debug("ExistenceCheck: ", req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)
	group, credential := pleasant.Read(req.Path)

	if(group == nil && credential == nil) {
		b.Logger().Debug("Path does not exist", req.Path)
		return false, nil
	}

	return true, nil
}

func (b *backend) credentialRead(credential *Credential) (map[string]interface{}) {
	d := map[string]interface{} {
		"id": credential.Id,
		"group": false,
		"created":   credential.Created,
		"modified":   credential.Modified,
	}

	if(credential.UserName != "") {
		d["user_name"] = credential.UserName
	}

	if(credential.Name != "") {
		d["name"] = credential.Name
	} else {
		d["name"] = credential.Id
	}

	if(credential.Password != "") {
		d["password"] = credential.Password
	}

	if(credential.Notes != "") {
		d["notes"] = credential.Notes
	}

	if(credential.Url != "") {
		d["url"] = credential.Url
	}

	if(credential.Expires != "") {
		d["expires"] = credential.Expires
	}

	custom_user_fields := map[string]string{}

	for key, value := range credential.CustomUserFields {
		custom_user_fields[key] = value
	}

	if(len(custom_user_fields) > 0) {
		d["custom_fields"] = custom_user_fields
	}

	attachments := map[string]string{}

	for _, attachment := range credential.Attachments {
		attachments[attachment.FileName] = attachment.FileData
	}

	if(len(attachments) > 0) {
		d["attachments"] = attachments
	}

	return d
}

func (b *backend) credentialGroupRead(group *CredentialGroup) (map[string]interface{}) {
	d := map[string]interface{} {
		"id": group.Id,
		"group": true,
		"name":   group.Name,
		"created":   group.Created,
		"modified":   group.Modified,
	}

	if(group.Expires != "") {
		d["expires"] = group.Expires
	}

	if(group.Notes != "") {
		d["notes"] = group.Notes
	}

	custom_user_fields := map[string]string{}

	for key, value := range group.CustomUserFields {
		custom_user_fields[key] = value
	}

	if(len(custom_user_fields) > 0) {
		d["custom_fields"] = custom_user_fields
	}

	return d
}

func (b *backend) pathKVRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathKVRead", req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)

	group, credential := pleasant.Read(req.Path)
	var d map[string]interface{}

	if(group == nil) {
		return nil, logical.ErrUnsupportedPath
	}

	if(credential == nil) {
		b.Logger().Debug("pathKVRead CredentialGroup: ", group.Name)
		d = b.credentialGroupRead(group)
	} else if(group != nil) {
		b.Logger().Debug("pathKVRead Credential: ", credential.Name)
		d = b.credentialRead(credential)
	}

	resp := &logical.Response{ Data: d }
	return resp, nil
}

func (b *backend) credentialUpdate(credential *Credential, data *framework.FieldData) {
	if(data.Get("name") != "") {
		credential.Name = data.Get("name").(string)
	}

	if(data.Get("user_name") != "") {
		credential.UserName = data.Get("user_name").(string)
	}

	if(data.Get("url") != "") {
		credential.Url = data.Get("url").(string)
	}

	if(data.Get("notes") != "") {
		credential.Notes = data.Get("notes").(string)
	}

	if(data.Get("password") != "") {
		credential.Password = data.Get("password").(string)
	}

	custom_fields := data.Get("custom_fields").(map[string]string)

	if(len(custom_fields) > 0) {
		credential.CustomUserFields = custom_fields
	}
}

func (b *backend) credentialGroupUpdate(group *CredentialGroup, data *framework.FieldData) {
	if(data.Get("name") != "") {
		group.Name = data.Get("name").(string)
	}

	if(data.Get("notes") != "") {
		group.Notes = data.Get("notes").(string)
	}

	custom_fields := data.Get("custom_fields").(map[string]string)

	if(len(custom_fields) > 0) {
		group.CustomUserFields = custom_fields
	}
}

func (b *backend) pathKVCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathKVCreate", req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)

	path_splitted := delete_empty(strings.Split(req.Path, "/"))
	name := path_splitted[len(path_splitted) - 1]
	path_splitted = path_splitted[0:len(path_splitted) - 1]

	b.Logger().Debug("New", name, strings.Join(path_splitted, "/"))

	group, credential := pleasant.Read(strings.Join(path_splitted, "/"))

	if(group != nil && credential == nil) {
		if(data.Get("group").(bool)) {
			new_group := &CredentialGroup{ Name: name, ParentId: group.Id}

			b.credentialGroupUpdate(new_group, data)
			new_group.Name = name

			pleasant.CreateCredentialGroup(new_group)

			new_group, _ = pleasant.Read(req.Path)

			return &logical.Response{
				Data: b.credentialGroupRead(new_group),
			}, nil
		} else {
			new_credential := &Credential{GroupId: group.Id}

			b.credentialUpdate(new_credential, data)
			new_credential.Name = name
			pleasant.CreateCredential(new_credential)

			_, new_credential = pleasant.Read(req.Path)

			return &logical.Response{
				Data: b.credentialRead(new_credential),
			}, nil
		}
	}

	return nil, logical.ErrUnsupportedPath
}

func (b *backend) pathKVUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathKVUpdate", req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)
	group, credential := pleasant.Read(req.Path)

	if(credential != nil) {
		b.credentialUpdate(credential, data)
		pleasant.UpdateCredential(credential)
		_, credential = pleasant.Read(req.Path)

		return &logical.Response{
			Data: b.credentialRead(credential),
		}, nil
	}

	if(group != nil) {
		b.credentialGroupUpdate(group, data)
		pleasant.UpdateCredentialGroup(group)
		group, _ = pleasant.Read(req.Path)

		return &logical.Response{
			Data: b.credentialGroupRead(group),
		}, nil
	}

	return nil, logical.ErrUnsupportedPath
}

func (b *backend) pathKVDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathKVDelete", req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)
	group, credential := pleasant.Read(req.Path)

	if(credential != nil) {
		pleasant.DeleteCredential(credential)
		return &logical.Response{}, nil
	}

	if(group != nil) {
		pleasant.DeleteCredentialGroup(group)
		return &logical.Response{}, nil
	}

	return nil, logical.ErrUnsupportedPath
}

func (b *backend) pathKVList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("List", req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)

	group, credential := pleasant.Read(req.Path)

	if(group == nil || credential != nil) {
		return nil, logical.ErrUnsupportedPath
	}

	vals := []string{}

	for _, group := range group.Children {
		vals = append(vals, group.Name+"/")
	}

	for _, credential := range group.Credentials {
		name := credential.Name

		if(name=="") {
			name = credential.Id
		}

		vals = append(vals, name)
	}

	return logical.ListResponse(vals), nil
}
