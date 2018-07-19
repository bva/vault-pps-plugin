package pleasant

import (
	"context"
	"strings"
	"regexp"
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

func extra_path_valid(extra_path string, strict bool) bool {
	if extra_path == "" {
		return true
	}

	if strict {
		matched, err := regexp.MatchString("^(custom_)?fields$", extra_path)
		if matched && err == nil {
			return true
		}

		matched, err = regexp.MatchString("^attachments$", extra_path)
		if matched && err == nil {
			return true
		}
	} else {
		matched, err := regexp.MatchString("^(custom_)?fields(/)?.*", extra_path)
		if matched && err == nil {
			return true
		}

		matched, err = regexp.MatchString("^attachments(/)?.*", extra_path)
		if matched && err == nil {
			return true
		}
	}

	return false
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	b.Logger().Debug("ExistenceCheck: ", req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)
	group, credential, extra_path := pleasant.Read(req.Path)

	if((group == nil && credential == nil) || !extra_path_valid(extra_path, false)) {
		b.Logger().Debug("Path does not exist", req.Path)
		return false, nil
	}

	return true, nil
}

func (b *backend) credentialRead(credential *Credential, extra_path string) (map[string]interface{}) {
	d := map[string]interface{} {}

	if extra_path == "custom_fields" {
		for key, value := range credential.CustomUserFields {
			d[key] = value
		}
	} else if extra_path == "attachments" {
		for _, attachment := range credential.Attachments {
			d[attachment.FileName] = attachment.FileData
		}
	} else {
		d["id"] = credential.Id
		d["created"] = credential.Created
		d["modified"] = credential.Modified

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
	}

	return d
}

func (b *backend) credentialGroupRead(group *CredentialGroup) (map[string]interface{}) {
	d := map[string]interface{} {
		"id": group.Id,
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

	group, credential, extra_path := pleasant.Read(req.Path)
	var d map[string]interface{}

	if(group == nil || !extra_path_valid(extra_path, true)) {
		return nil, logical.ErrUnsupportedPath
	}

	if(credential == nil) {
		b.Logger().Debug("pathKVRead CredentialGroup: ", group.Name)
		d = b.credentialGroupRead(group)
	} else if(group != nil) {
		b.Logger().Debug("pathKVRead Credential: ", credential.Name)
		d = b.credentialRead(credential, extra_path)
	}

	resp := &logical.Response{ Data: d }
	return resp, nil
}

func (b *backend) credentialDelete(credential *Credential, data *framework.FieldData, extra_path string) {
	extra_path_splitted := strings.SplitN(extra_path, "/", 2)
	extra, variable := extra_path_splitted[0], extra_path_splitted[1]

	if variable == "" {
		return
	}

	if extra == "fields" {
		if variable == "name" {
			credential.Name = ""
		}

		if variable == "user_name" {
			credential.UserName = ""
		}

		if variable == "url" {
			credential.Url = ""
		}

		if variable == "notes" {
			credential.Notes = ""
		}

		if variable == "password" {
			credential.Password = ""
		}

		if variable == "expires" {
			credential.Expires = ""
		}
	} else if extra == "custom_fields" {
		delete(credential.CustomUserFields, variable)
	} else if extra == "attachments" {
		attachments := map[string]string{}

		for _, attachment := range credential.Attachments {
			attachments[attachment.FileName] = attachment.FileData
		}

		credential.Attachments = []Attachment{}

		for file_name, file_data := range attachments {
			if file_name != variable {
				attachment := Attachment{CredentialObjectId: credential.Id, FileName: file_name, FileData: file_data}
				credential.Attachments = append(credential.Attachments, attachment)
			}
		}
	}
}

func (b *backend) credentialUpdate(credential *Credential, data *framework.FieldData, extra_path string) {
	if extra_path == "" {
		extra_path = "fields"
	}

	if extra_path == "fields" {
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

		if(data.Get("expires") != "") {
			credential.Expires = data.Get("expires").(string)
		}

	} else if extra_path == "custom_fields" {
		custom_fields := credential.CustomUserFields

		for field, _ := range data.Raw {
			custom_fields[field] = data.Raw[field].(string)
		}
	} else if extra_path == "attachments" {
		attachments := map[string]string{}

		for _, attachment := range credential.Attachments {
			attachments[attachment.FileName] = attachment.FileData
		}

		for field, field_value := range data.Raw {
			attachments[field] = field_value.(string)
		}

		credential.Attachments = []Attachment{}

		for file_name, file_data := range attachments {
			attachment := Attachment{CredentialObjectId: credential.Id, FileName: file_name, FileData: file_data}
			credential.Attachments = append(credential.Attachments, attachment)
		}
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

	group, credential, extra_path := pleasant.Read(strings.Join(path_splitted, "/"))

	if(group != nil && credential == nil && extra_path_valid(extra_path, true)) {
		if(data.Get("group").(bool)) {
			new_group := &CredentialGroup{ Name: name, ParentId: group.Id}

			b.credentialGroupUpdate(new_group, data)
			new_group.Name = name

			pleasant.CreateCredentialGroup(new_group)

			new_group, _, _ = pleasant.Read(req.Path)

			return &logical.Response{
				Data: b.credentialGroupRead(new_group),
			}, nil
		} else if (extra_path_valid(extra_path, true) && (extra_path == "" || extra_path == "fields")) {
			new_credential := &Credential{GroupId: group.Id}

			b.credentialUpdate(new_credential, data, "fields")
			new_credential.Name = name
			pleasant.CreateCredential(new_credential)

			_, new_credential, _ = pleasant.Read(req.Path)

			return &logical.Response{
				Data: b.credentialRead(new_credential, "fields"),
			}, nil
		}
	}

	return nil, logical.ErrUnsupportedPath
}

func (b *backend) pathKVUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathKVUpdate", req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)
	group, credential, extra_path := pleasant.Read(req.Path)

	if(credential != nil && extra_path_valid(extra_path, true)) {
		b.credentialUpdate(credential, data, extra_path)
		pleasant.UpdateCredential(credential)
		_, credential, _ = pleasant.Read(req.Path)

		return &logical.Response{
			Data: b.credentialRead(credential, extra_path),
		}, nil
	} else if(group != nil) {
		b.credentialGroupUpdate(group, data)
		pleasant.UpdateCredentialGroup(group)
		group, _, _ = pleasant.Read(req.Path)

		return &logical.Response{
			Data: b.credentialGroupRead(group),
		}, nil
	}

	return nil, logical.ErrUnsupportedPath
}

func (b *backend) pathKVDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathKVDelete", req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)
	group, credential, extra_path := pleasant.Read(req.Path)

	if(credential != nil && extra_path_valid(extra_path, false)) {
		if extra_path == "" {
			pleasant.DeleteCredential(credential)
		} else {
			b.credentialDelete(credential, data, extra_path)
			pleasant.UpdateCredential(credential)
		}

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

	group, credential, extra_path  := pleasant.Read(req.Path)

	if(group == nil || extra_path != "") {
		return nil, logical.ErrUnsupportedPath
	}

	vals := []string{}

	if credential != nil {
		vals = append(vals, "fields")
		vals = append(vals, "custom_fields")
		vals = append(vals, "attachments")
	} else {
		for _, group := range group.Children {
			vals = append(vals, group.Name + "/")
		}

		for _, credential := range group.Credentials {
			name := credential.Name

			if(name == "") {
				name = credential.Id
			}

			vals = append(vals, name + "/")
		}
	}

	return logical.ListResponse(vals), nil
}
