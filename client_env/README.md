# Client environments

This directory holds **customer-specific** infrastructure knowledge used by the
knowledge-base MCP tools (`kb_list_clients`, `kb_get_client_infra`).

## What is safe to commit

| Path | Purpose |
|------|---------|
| `all_clients/` | Generic templates (not treated as a real client) |
| `env_rules.json` | Shared classification rules |
| `example_client/` | Fictional template you can copy |
| `README.md` | This file |

## What stays private

Create one folder per customer using the `*_client` suffix, for example:

```
client_env/acme_corp_client/
  internal_subnets.json
  internal_servers.json
  internal_users.json
  naming_schemas.json
```

Those folders are gitignored so customer names, subnets, users, and naming
schemas are not committed. Copy `example_client/` as a starting point:

```bash
cp -a client_env/example_client client_env/your_customer_client
```

Do not put real customer data in `example_client/` or `all_clients/`.
