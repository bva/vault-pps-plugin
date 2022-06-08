package pleasant

import (
	"context"
	"strings"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/framework"
)

// kvPaths is used to test CRUD and List operations. It is a simplified
// version of the passthrough backend that only accepts string values.
func kvPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: ".*",
			Fields: map[string]*framework.FieldSchema{
				"Id":     &framework.FieldSchema{Type: framework.TypeString},
				"Name":     &framework.FieldSchema{Type: framework.TypeString},
				"Username":     &framework.FieldSchema{Type: framework.TypeString},
				"Password":  &framework.FieldSchema{Type: framework.TypeString},
				"Notes":     &framework.FieldSchema{Type: framework.TypeString},
				"Url":   &framework.FieldSchema{Type: framework.TypeString},
				"Created":   &framework.FieldSchema{Type: framework.TypeString},
				"Modified":  &framework.FieldSchema{Type: framework.TypeString},
				"Group":   &framework.FieldSchema{Type: framework.TypeString},
				"Expires":   &framework.FieldSchema{Type: framework.TypeString},
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
	b.Logger().Debug("ExistenceCheck path " + req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)
	group, credential := pleasant.Read(req.Path)

	if(group == nil && credential == nil) {
		b.Logger().Debug("Path does not exist", req.Path)
		return false, nil
	}

	return true, nil
}

func (b *backend) credentialRead(credential *Credential) (map[string]interface{}) {
	d := map[string]interface{}{}

	d["Id"] = credential.Id
	d["Created"] = credential.Created
	d["Modified"] = credential.Modified

	if(credential.Username != "") {
		d["Username"] = credential.Username
	}

	if(credential.Name != "") {
		d["Name"] = credential.Name
	}

	if(credential.Password != "") {
		d["Password"] = credential.Password
	}

	if(credential.Notes != "") {
		d["Notes"] = credential.Notes
	}

	if(credential.Url != "") {
		d["Url"] = credential.Url
	}

	if(credential.Expires != "") {
		d["Expires"] = credential.Expires
	}

	for name, value := range credential.CustomUserFields {
		d["Custom:" + name] = value
	}

	for _, attachment := range credential.Attachments {
		d["Attachment:" + attachment.FileName] = attachment.FileData
	}

	return d
}

func (b *backend) pathKVRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathKVRead", req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)

	group, credential := pleasant.Read(req.Path)

	d := map[string]interface{}{}

	if(group != nil && credential != nil) {
		b.Logger().Debug("pathKVRead Credential: ", credential.Name)
		d = b.credentialRead(credential)
		d["Password"] = pleasant.RequestCredentialPassword(credential.Id)
	}

	if len(d) > 0 {
		resp := &logical.Response{ Data: d }
		return resp, nil
	}

	return nil, logical.ErrUnsupportedPath
}

func (b *backend) credentialUpdate(credential *Credential, data *framework.FieldData) {
	if(data.Get("Name") != "") {
		credential.Name = data.Get("Name").(string)
	}

	if(data.Get("Username") != "") {
		credential.Username = data.Get("Username").(string)
	}

	if(data.Get("Url") != "") {
		credential.Url = data.Get("Url").(string)
	}

	if(data.Get("Notes") != "") {
		credential.Notes = data.Get("Notes").(string)
	}

	if(data.Get("Password") != "") {
		credential.Password = data.Get("Password").(string)
	}

	if(data.Get("Expires") != "") {
		credential.Expires = data.Get("Expires").(string)
	}

	custom_fields := map[string]string{}

	for field_name, field_value := range credential.CustomUserFields {
		custom_fields[field_name] = field_value
	}

	attachments := map[string]string{}

	for _, attachment := range credential.Attachments {
		attachments[attachment.FileName] = attachment.FileData
	}


	for field, value := range data.Raw {
		if strings.HasPrefix(field, "Custom:") {
			custom_field := strings.TrimPrefix(field, "Custom:")

			if value == nil || len(value.(string)) == 0 {
				delete(custom_fields, custom_field)
			} else {
				custom_fields[custom_field] = value.(string)
			}
		} else if strings.HasPrefix(field, "Attachment:") {
			attachment_field := strings.TrimPrefix(field, "Attachment:")

			if value == nil || len(value.(string)) == 0 {
				delete(attachments, attachment_field)
			} else {
				attachments[attachment_field] = value.(string)
			}
		}
	}

	credential.CustomUserFields = custom_fields
	credential.Attachments = []Attachment{}

	for file_name, file_data := range attachments {
		attachment := Attachment{CredentialObjectId: credential.Id, FileName: file_name, FileData: file_data}
		credential.Attachments = append(credential.Attachments, attachment)
	}
}

func (b *backend) credentialGroupUpdate(group *CredentialGroup, data *framework.FieldData) {
	if(data.Get("Name") != "") {
		group.Name = data.Get("Name").(string)
	}

	if(data.Get("Notes") != "") {
		group.Notes = data.Get("Notes").(string)
	}
}

func (b *backend) pathKVCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Logger()
	logger.Debug("pathKVCreate path " + req.Path)

	path_splitted := strings.Split(req.Path, "/")

	name := path_splitted[len(path_splitted)-1:][0]
	path := strings.Join(path_splitted[:len(path_splitted)-1], "/")

	pleasant, _ := b.Session(ctx, req.Storage)
 	group, credential := pleasant.Read(path)

	if credential != nil {
		return nil, logical.ErrUnsupportedPath
	}

	if group != nil && data.Get("Group") == "true" {
		new_group := &CredentialGroup{ Name: name, ParentId: group.Id }
		b.credentialGroupUpdate(new_group, data)
		new_group.Name = name

		pleasant.CreateCredentialGroup(new_group)
		new_group, _ = pleasant.Read(req.Path)

		return &logical.Response{}, nil
	} else if group != nil {
		new_credential := &Credential{ GroupId: group.Id }
		b.credentialUpdate(new_credential, data)
		new_credential.Name = name

		pleasant.CreateCredential(new_credential)

		_, new_credential = pleasant.Read(req.Path)

		d := b.credentialRead(new_credential)
		d["Password"] = pleasant.RequestCredentialPassword(d["Id"].(string))

		return &logical.Response{
			Data: d,
		}, nil
	}

	return nil, logical.ErrUnsupportedPath
}

func (b *backend) pathKVUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathKVUpdate", req.Path)

	if len(data.Raw) == 0 {
		return &logical.Response{}, nil
	}

	pleasant, _ := b.Session(ctx, req.Storage)
	group, credential := pleasant.Read(req.Path)

	if credential != nil {
		credential.Password = pleasant.RequestCredentialPassword(credential.Id)
		b.credentialUpdate(credential, data)
		pleasant.UpdateCredential(credential)

		d := b.credentialRead(credential)

		return &logical.Response{
			Data: d,
		}, nil
	} else if group != nil {
		b.credentialGroupUpdate(group, data)
		pleasant.UpdateCredentialGroup(group)

		return &logical.Response{}, nil
	}

	return nil, logical.ErrUnsupportedPath
}

func (b *backend) pathKVDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathKVDelete", req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)
	group, credential := pleasant.Read(req.Path)

	if credential != nil {
		pleasant.DeleteCredential(credential)
		return &logical.Response{}, nil
	} else if group != nil {
		pleasant.DeleteCredentialGroup(group)
		return &logical.Response{}, nil
	}

	return nil, logical.ErrUnsupportedPath
}

func (b *backend) pathKVList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("List path " + req.Path)

	pleasant, _ := b.Session(ctx, req.Storage)

	group, credential := pleasant.Read(req.Path)

	if(group == nil || credential != nil) {
		return nil, logical.ErrUnsupportedPath
	}

	vals := []string{}

	const ( GROUP = 0; SECRET = 1 )

	type Entry struct {
		Id string
		Type int
	}

	entries := make(map[string][]Entry)

	for _, group := range group.Children {
		name := group.Name

		entries[name] = append(entries[name], Entry { group.Id, GROUP })
	}

	for _, credential := range group.Credentials {
		name := credential.Name
		if name == "" {
			name = credential.Username
		}

		if name == "" {
			name = credential.Id
		}

		entries[name] = append(entries[name], Entry { credential.Id, SECRET })
	}

	for name, list := range entries {
		for _, entry := range list {
			id := name

			if len(list) > 1 {
				id += "[" + entry.Id + "]"
			}

			if entry.Type == GROUP {
				id += "/"
			}

			vals = append(vals, id)
		}
	}

	response := logical.ListResponse(vals)
	return response, nil
}
