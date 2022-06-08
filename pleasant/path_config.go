package pleasant

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/framework"
)

func pathConfigAccess(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "config/access",
			Fields: map[string]*framework.FieldSchema{
				"url": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Pleasant Password server URL",
				},

				"user_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Pleasant Password user name",
				},

				"password": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Pleasant Password user password",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathConfigAccessRead,
				logical.UpdateOperation: b.pathConfigAccessWrite,
			},
		},
	}
}

func (b *backend) readConfigAccess(ctx context.Context, storage logical.Storage) (*accessConfig, error) {
	entry, err := storage.Get(ctx, "config/access")

	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, errwrap.Wrapf("access credentials for the backend itself haven't been configured; please configure them at the '/config/access' endpoint", nil)
	}

	conf := &accessConfig{}
	if err := entry.DecodeJSON(conf); err != nil {
		return nil, errwrap.Wrapf("error reading pleasant password access configuration: {{err}}", err)
	}

	return conf, nil
}

func (b *backend) pathConfigAccessRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	conf, err := b.readConfigAccess(ctx, req.Storage)

	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if conf == nil {
		return nil, fmt.Errorf("no user error reported but pleasant password access configuration not found")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"url": conf.Url,
			"user_name":  conf.UserName,
			"password":  conf.Password,
		},
	}, nil
}

func (b *backend) pathConfigAccessWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathConfigAccessWrite")

	entry, err := logical.StorageEntryJSON("config/access", accessConfig{
		Url: data.Get("url").(string),
		UserName:  data.Get("user_name").(string),
		Password:   data.Get("password").(string),
	})
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.ResetSession(ctx)

	return nil, nil
}

type accessConfig struct {
	Url  string `json:"url"`
	UserName string `json:"user_name"`
	Password   string `json:"password"`
}
