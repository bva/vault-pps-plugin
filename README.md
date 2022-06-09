# Vault plugin for Pleasant Password Server

Plugin for Hashicorp's Vault, which connect it to Pleasant Password Server.

## Installation

Download and build Go plugin sources:

```
go install github.com/bva/vault-pps-plugin@1.0.0
```
You will need to define a plugin directory using the plugin_directory configuration directive in Vault configutration,
then place the vault-pss executable generated above in the directory.

```bash
cp $GOPATH/bin/vault-pps-plugin /etc/vault/plugins
export VAULT_PPS_SHA256_SUM=`shasum -a 256 /etc/vault/plugins/vault-pps-plugin | awk '{ print $1; }'`
```

Register vault-pps-plugin plugin with vault and mount it in Vault _pps_ path:

```bash
vault write sys/plugins/catalog/vault-pps-plugin sha_256=$VAULT_PPS_SHA256_SUM command=vault-pps-plugin
vault secrets enable -path=pps -plugin-name=vault-pps-plugin plugin
vault write pps/config/access url="$PPS_URL" user_name="$PPS_USER" password="$PPS_PASSWORD"
```

| Variable             | Description                                                                         |
| ---------------------|-------------------------------------------------------------------------------------|
| PPS_URL              | URL for Pleasant Password Server (https://localhost:8001/)                          |
| PPS_USER             | Username in Pleasant Password Server under which Vault plugin connects              |
| PPS_PASSWORD         | Password for username in Pleasant Password Server under which Vault plugin connects |


Accessing Pleasant Password secrets from Vault:

```bash
vault kv get pps/<folder>/<secret>
```
