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

Licensed under either of

 * [Apache License, Version 2.0]
   ([LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) or [apache-2.0-license-website])
 * MIT License
   ([LICENSES/MIT.txt](LICENSES/MIT.txt) or <https://opensource.org/license/mit>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

[Apache License, Version 2.0]: LICENSES/Apache-2.0.txt
[apache-2.0-license-website]: http://www.apache.org/licenses/LICENSE-2.0
