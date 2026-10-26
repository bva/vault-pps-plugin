# Vault plugin for Pleasant Password Server

Plugin for Hashicorp's Vault, which connects it to Pleasant Password Server.

> **Note:** This plugin supports **Pleasant Password Server REST API v4** (`/api/v4/rest/`, Pleasant Password Server `7.0` – `7.9.x`) only.

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

| Parameter                         | Default | Description                                                                                 |
| ----------------------------------|---------|---------------------------------------------------------------------------------------------|
| `url`                             | —       | URL for Pleasant Password Server (e.g. `https://localhost:8001/`)                           |
| `user_name`                       | —       | Username in Pleasant Password Server under which Vault plugin connects                      |
| `password`                        | —       | Password for username in Pleasant Password Server under which Vault plugin connects         |
| `tree_ttl`                        | `300s`  | Full credential tree refresh interval in seconds or Go duration (e.g. `300`, `5m`, `10m`)   |
| `miss_cooldown`                   | `30s`   | Cooldown between partial group refreshes on cache miss in seconds or Go duration (`30s`)    |
| `http_timeout`                    | `30s`   | HTTP client timeout for Pleasant Password Server requests in seconds or Go duration (`30s`) |
| `experimental_invalidate_on_miss` | `false` | When `true`, reloads the nearest cached parent group from PPS on Read/List cache miss       |


Accessing Pleasant Password secrets from Vault:

```bash
vault kv get pps/<folder>/<secret>
```

Reading credential metadata (`Id`, `Name`, `Username`, `Url`, `Notes`, `Custom:*`, `Attachment:*`) without fetching the plaintext password from Pleasant Password Server:

```bash
vault read pps/<folder>/<secret> metadata=true
# or via HTTP API: GET /v1/pps/<folder>/<secret>?metadata=true
```
