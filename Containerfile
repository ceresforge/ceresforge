ARG CONTAINER_IMAGE=debian:trixie-slim

FROM ${CONTAINER_IMAGE} AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        pkg-config \
        npm \
        rustup \
    && rm -rf /var/lib/apt/lists/* \
    && rustup default stable

WORKDIR /package/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml \
    frontend/svelte.config.js frontend/tsconfig.json \
    .
RUN npm install -g pnpm@latest-10 && pnpm install

WORKDIR /package
COPY Cargo.toml Cargo.lock build.rs .
COPY .sqlx ./.sqlx/
COPY migrations ./migrations/
COPY frontend ./frontend/
COPY src ./src/
ENV SQLX_OFFLINE="true"
RUN cargo build --release

FROM ${CONTAINER_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        nodejs \
        xmlsec1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /package/target/release/ceresforge \
    /usr/local/bin/ceresforge
COPY --from=build /package/frontend/build /opt/ceresforge/frontend/
ENV FRONTEND_DIR "/opt/ceresforge/frontend"
CMD ["ceresforge", "server"]
