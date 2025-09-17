# CeresForge

A web platform for learning, creating, and testing software.

## Building

```sh
cargo install sqlx-cli
```

```sh
podman run --name ceresforge-postgres -d -e POSTGRES_USER="ceresforge" -e POSTGRES_INITDB_ARGS="--data-checksums" -e POSTGRES_HOST_AUTH_METHOD="trust" -p 5432:5432 postgres
```
