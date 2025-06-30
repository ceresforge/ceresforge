ARG CONTAINER_IMAGE=debian:trixie-slim

FROM $CONTAINER_IMAGE AS build
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential \
        rustup \
    && rm -rf /var/lib/apt/lists/* \
    && rustup default stable
WORKDIR /package
COPY .sqlx ./.sqlx/
COPY migrations ./migrations/
COPY frontend ./frontend/
COPY src ./src/
COPY Cargo.toml Cargo.lock build.rs .
ENV SQLX_OFFLINE="true"
RUN cargo build --release

FROM $CONTAINER_IMAGE
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        xmlsec1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /package/target/release/ceresforge /usr/local/bin/ceresforge
CMD ["ceresforge", "server"]
