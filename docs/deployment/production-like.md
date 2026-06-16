# SentinelFlow Production-Like Single-Node Deployment

This is a hardened single-node shape for pilots. It is not a distributed worker
deployment and does not add P6 features.

## Supported Backend

v1.0-rc supports SQLite as the active store:

```text
/srv/sentinelflow/.sentinelflow/state.db
```

PostgreSQL is not enabled by the current API/Core store implementation. If a
pilot environment requires PostgreSQL, keep the secret and network plumbing
outside SentinelFlow until a future backend is implemented; do not configure a
PostgreSQL URL expecting silent fallback.

Reserved secret pattern:

```sh
# Reserved for a future PostgreSQL backend. Not consumed by v1.0-rc.
export SENTINELFLOW_DATABASE_URL_FILE=/run/secrets/sentinelflow_database_url
```

Secrets must come from environment variables or secret files. Do not commit real
tokens, database URLs, passwords, or production hostnames.

## Directories

Create a dedicated service user and persistent directories:

```sh
sudo useradd --system --home /srv/sentinelflow --shell /usr/sbin/nologin sentinelflow
sudo install -d -o sentinelflow -g sentinelflow /srv/sentinelflow/.sentinelflow
sudo install -d -o sentinelflow -g sentinelflow /srv/sentinelflow/.sentinelflow/plugins
sudo install -d -o sentinelflow -g sentinelflow /srv/sentinelflow/.sentinelflow/reports
sudo install -d -o sentinelflow -g sentinelflow /srv/sentinelflow/.sentinelflow/logs
```

Use `docs/deployment/config-production-like.yaml` as the starting CLI/API
configuration.

## Runtime Environment

```sh
export SENTINELFLOW_API_BIND=127.0.0.1:8080
export SENTINELFLOW_WORKSPACE_DIR=/srv/sentinelflow/.sentinelflow
export SENTINELFLOW_SCHEMA_ROOT=/opt/sentinelflow
export SENTINELFLOW_LOG_LEVEL=warn
```

Place a reverse proxy with TLS and authentication in front of the API for any
shared pilot. The bundled development identity provider is not production auth.

## Backup

Stop the API or take an application-quiesced copy, then back up:

```sh
sqlite3 /srv/sentinelflow/.sentinelflow/state.db ".backup '/backup/sentinelflow-state.db'"
tar -C /srv/sentinelflow/.sentinelflow -czf /backup/sentinelflow-artifacts.tgz \
  plugins tasks runs results reports audit approvals logs
```

## Restore

```sh
systemctl stop sentinelflow-api
install -d -o sentinelflow -g sentinelflow /srv/sentinelflow/.sentinelflow
cp /backup/sentinelflow-state.db /srv/sentinelflow/.sentinelflow/state.db
tar -C /srv/sentinelflow/.sentinelflow -xzf /backup/sentinelflow-artifacts.tgz
chown -R sentinelflow:sentinelflow /srv/sentinelflow/.sentinelflow
systemctl start sentinelflow-api
```

After restore, verify:

```sh
curl -fsS http://127.0.0.1:8080/health
```

Then run a safe `example-echo` task before admitting users.
