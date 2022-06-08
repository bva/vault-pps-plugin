package main

import (
	"log"
	"os"
	"net/http"
        "crypto/tls"
        "github.com/bva/vault-pps-plugin/pleasant"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
        http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:]) // Ignore command, strictly parse flags

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	factoryFunc := pleasant.FactoryType(logical.TypeLogical)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: factoryFunc,
		TLSProviderFunc:    tlsProviderFunc,
	})

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
