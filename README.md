# CeresForge

A web platform for learning, creating, and testing software.

## Building

```sh
cargo install sqlx-cli
```

```sh
podman run \
  --name ceresforge-postgres \
  -d \
  -e POSTGRES_USER="ceresforge" \
  -e POSTGRES_INITDB_ARGS="--data-checksums" \
  -e POSTGRES_HOST_AUTH_METHOD="trust" \
  -p 5432:5432 \
  postgres
```

## License

Licensed under the [Apache License, Version 2.0] or the [MIT License], at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the [Apache License, Version 2.0], shall be dual licensed as above,
without any additional terms or conditions.

[Apache License, Version 2.0]: LICENSES/Apache-2.0.txt
[MIT License]: LICENSES/MIT.txt
