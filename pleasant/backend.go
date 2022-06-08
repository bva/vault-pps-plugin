package pleasant

import (
	"context"
	"sync"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/framework"
)

var(
    backend_singleton *backend
)

// FactoryType is a wrapper func that allows the Factory func to specify
// the backend type for the mock backend plugin instance.
func FactoryType(backendType logical.BackendType) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		if backend_singleton == nil {
			backend_singleton = Backend()

			backend_singleton.BackendType = backendType
			if err := backend_singleton.Setup(ctx, conf); err != nil {
				return nil, err
			}
		}

		return *backend_singleton, nil
	}
}

// Backend returns a private embedded struct of framework.Backend.
func Backend() *backend {
	var b backend

	b.Backend = &framework.Backend{
		Help: "Pleasant Password management plugin",

		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/access",
			},
		},

		Paths: framework.PathAppend(
			pathConfigAccess(&b),
			kvPaths(&b),
		),
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,

		Clean: b.ResetSession,
		Invalidate:  b.invalidate,
	}

	return &b
}

func (b *backend) Session(ctx context.Context, s logical.Storage) (*Pleasant, error) {
	logger := b.Logger()

	logger.Debug("Session")
        b.lock.Lock()
        defer b.lock.Unlock()

        if b.pleasant != nil {
		logger.Debug("Returning cached pleasant session")
		return b.pleasant, nil
        }

	accessConfig, err :=  b.readConfigAccess(ctx, s)
	logger.Debug("Creating new pleasant session")

        if err != nil {
                return nil, err
        }

	b.pleasant = NewPleasant(b)
	b.pleasant.Login(accessConfig.Url, accessConfig.UserName, accessConfig.Password)

        return b.pleasant, nil
}

// ResetSession forces creation of a new connection next time Session() is called.
func (b *backend) ResetSession(_ context.Context) {
	b.Logger().Debug("ResetSession")

        b.lock.Lock()
        defer b.lock.Unlock()

        if b.pleasant != nil {
		b.Logger().Debug("Logging out from Pleasant")
                b.pleasant.Logout()
        }

        b.pleasant = nil
}

func (b *backend) invalidate(ctx context.Context, key string) {
	b.Logger().Debug("Invalidate")

        switch key {
        case "config/access":
                b.ResetSession(ctx)
        }
}

type backend struct {
	*framework.Backend

	pleasant *Pleasant
	lock    sync.Mutex
}
