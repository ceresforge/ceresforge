ARG CONTAINER_IMAGE=debian:trixie-slim

FROM $CONTAINER_IMAGE AS build
RUN apt-get update \
    && apt-get install -y \
        build-essential \
        rustup \
    && rm -rf /var/lib/apt/lists/*
RUN rustup default nightly
WORKDIR /package
COPY frontend ./frontend/
COPY src ./src/
COPY Cargo.toml Cargo.lock .
RUN cargo build --release

FROM $CONTAINER_IMAGE
COPY --from=build /package/target/release/ceresforge /usr/local/bin/ceresforge
CMD ["ceresforge"]
