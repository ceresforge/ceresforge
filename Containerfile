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
        woff2 \
    && rm -rf /var/lib/apt/lists/* \
    && rustup default stable \
    && npm install -g pnpm@latest-10

WORKDIR /package
COPY . /package
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
COPY --from=build /package/target/release/ceresforge /usr/local/bin/ceresforge
COPY --from=build /package/apps/web/build /opt/ceresforge/apps/web/
ENV WEB_DIR "/opt/ceresforge/apps/web"
CMD ["ceresforge", "server"]
