# Vault plugin for Pleasant Password Server

## Installation
Download and build Go plugin sources

```bash
vault write sys/plugins/catalog/vault-pps sha_256=$shasum command=vault-ppps
vault secrets enable -path=pps -plugin-name=vault-pps plugin
vault write pps/config/access url="$PPS_URL" user_name="$PPS_USER" password="$PPS_PASSWORD"
```
