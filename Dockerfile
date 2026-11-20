# syntax=docker/dockerfile:1
#
# Imagen de klav-server. Uso y opciones: docs/self-hosting.md.
# Railway usa deploy/railway/Dockerfile (§8): si cambias el build, cámbialo también allí.

# sccache for the build stage, only when CI asks for it: `--build-arg
# KLAV_SCCACHE=on` plus its ci-cache session (WebDAV endpoint and token) as
# BuildKit secrets. klav-server's crates then compile through the remote
# cache, and a change in crates/ recompiles only what changed. Without them
# (Railway, a plain `docker build`) `sccache` is the empty stage, nothing is
# downloaded and cargo builds as before: same image either way. Version and
# SHA-256 are the ones the ci-cache setup action pins.
ARG KLAV_SCCACHE=off
ARG TARGETARCH
FROM scratch AS sccache-off
FROM scratch AS sccache-on-amd64
ADD --checksum=sha256:aa73c7270c997894038c0d8f0d297865f57569e1687883322bc431713d4bb9dd \
    https://github.com/mozilla/sccache/releases/download/v0.19.0/sccache-v0.19.0-x86_64-unknown-linux-musl.tar.gz /sccache.tar.gz
FROM scratch AS sccache-on-arm64
ADD --checksum=sha256:3e47fc4a71b1ddd1b4294a0de9d34498922fdf41e3cd0bda5df3954e3d6deb9d \
    https://github.com/mozilla/sccache/releases/download/v0.19.0/sccache-v0.19.0-aarch64-unknown-linux-musl.tar.gz /sccache.tar.gz
FROM sccache-on-${TARGETARCH} AS sccache-on
FROM sccache-${KLAV_SCCACHE} AS sccache

# Imágenes base fijadas por digest (índice multiplataforma). La de rust lleva
# la versión de rust-toolchain.toml, para que el binario que se publica salga
# del mismo rustc con el que la CI corre clippy y las pruebas. Para subirlas,
# en los tres Dockerfiles a la vez (este, deploy/railway/Dockerfile y
# deploy/proxy/Dockerfile):
#   docker buildx imagetools inspect rust:<versión>-slim-bookworm   # línea «Digest:»
#   docker buildx imagetools inspect debian:bookworm-slim
FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build
WORKDIR /src
# Solo lo que lee `cargo build -p klav-server`: los manifiestos del workspace
# y crates/ entero, porque cargo necesita el Cargo.toml de cada miembro para
# resolver el workspace aunque no lo compile. Con `COPY . .`, cualquier cambio
# en scripts/, deploy/ o la raíz invalidaba la capa compilada en la caché de
# la CI y klav-server se volvía a compilar. Si el build llega a leer algo de
# fuera de crates/ (un .cargo/config.toml, un include_str! de otra carpeta),
# añade su COPY aquí y en deploy/railway/Dockerfile: sin él, el build no lo ve.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
# With the secrets and sccache-on, cargo compiles through sccache and its
# stats close the step's log. Its server listens on a socket in /tmp, never
# on a port the host's sccache may hold. If anything fails before cargo
# starts (no secret, a server that cannot reach the cache), cargo uses plain
# rustc; nothing of sccache stays in the layer. The secrets never reach a
# layer, the image history or BuildKit's cache key. Railway's Dockerfile has
# the same lines without the mounts, so there this is plain cargo.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    --mount=type=bind,from=sccache,target=/opt/sccache \
    --mount=type=secret,id=sccache_webdav_endpoint,env=SCCACHE_WEBDAV_ENDPOINT,required=false \
    --mount=type=secret,id=sccache_webdav_token,env=SCCACHE_WEBDAV_TOKEN,required=false \
    if [ -n "${SCCACHE_WEBDAV_TOKEN:-}" ] && [ -s /opt/sccache/sccache.tar.gz ]; then \
        export SCCACHE_DIR=/tmp/sccache/dir SCCACHE_SERVER_UDS=/tmp/sccache/server.sock \
            SCCACHE_IDLE_TIMEOUT=0 SCCACHE_WEBDAV_DISABLE_CREATE_DIR=true SCCACHE_IGNORE_SERVER_IO_ERROR=1; \
        if mkdir -p /tmp/sccache \
            && tar -xzf /opt/sccache/sccache.tar.gz -C /tmp/sccache --strip-components=1 --wildcards '*/sccache' \
            && /tmp/sccache/sccache --start-server >/dev/null 2>&1; then \
            export RUSTC_WRAPPER=/tmp/sccache/sccache; \
            echo "sccache: compiling through the CI cache"; \
        else \
            echo "sccache: did not start, compiling without it"; \
        fi; \
    fi; \
    cargo build --release --locked -p klav-server \
    && cp target/release/klav-server /usr/local/bin/klav-server \
    && if [ -n "${RUSTC_WRAPPER:-}" ]; then \
        "$RUSTC_WRAPPER" --show-stats || true; \
        "$RUSTC_WRAPPER" --stop-server >/dev/null 2>&1 || true; \
    fi \
    && rm -rf /tmp/sccache

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
# ca-certificates: the APNs client (rustls) verifies Apple with the
# system roots, and the slim image ships none.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 klav \
    && useradd --system --uid 10001 --gid klav --no-create-home --shell /usr/sbin/nologin klav \
    && mkdir /data \
    && chown klav:klav /data \
    && chmod 700 /data
COPY --from=build /usr/local/bin/klav-server /usr/local/bin/klav-server

ENV KLAV_LISTEN=0.0.0.0:8080 \
    KLAV_DATABASE_URL=sqlite:///data/klav.db \
    KLAV_DATA_DIR=/data \
    KLAV_LOG_FORMAT=json
USER klav:klav
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --start-interval=2s --retries=3 \
    CMD ["klav-server", "healthcheck"]
ENTRYPOINT ["klav-server"]
