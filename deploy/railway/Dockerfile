# syntax=docker/dockerfile:1
#
# klav-server image for Railway. Guide: docs/self-hosting.md, section 8.
#
# Same build and runtime as the root Dockerfile (keep them in step), with
# three differences that Railway needs:
#   - no mounts: Railway only accepts cache mounts, and only with an `id`
#     that carries the service ID, which a template cannot know. So no
#     sccache either (the root Dockerfile's bind and secret mounts);
#   - no `VOLUME`: the volume is attached in Railway, at /data;
#   - it starts as root, because Railway mounts the volume owned by root.
#     The entrypoint hands /data to `klav` (UID 10001) and drops every
#     privilege before starting the server, which never runs as root.

# Base images pinned by digest (multi-platform index), the same in both
# Dockerfiles. The rust one carries rust-toolchain.toml's release, so the
# shipped binary comes from the rustc CI lints and tests with. To bump them,
# in both files at once:
#   docker buildx imagetools inspect rust:<release>-slim-bookworm   # "Digest:" line
#   docker buildx imagetools inspect debian:bookworm-slim
FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build
WORKDIR /src
# Only what `cargo build -p klav-server` reads: the workspace manifests and
# all of crates/ (cargo needs every member's Cargo.toml to resolve the
# workspace, even the members it does not build). The same two lines as the
# root Dockerfile: CI compares the two build stages.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
# The root Dockerfile's compile, without its mounts: Railway's builder
# rejects every mount but its own cache form. With no sccache archive and no
# secret, the `if` is false and this is plain `cargo build`. Keep the lines
# the same as there, so CI can reuse that image's binary.
RUN if [ -n "${SCCACHE_WEBDAV_TOKEN:-}" ] && [ -s /opt/sccache/sccache.tar.gz ]; then \
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
COPY deploy/railway/entrypoint.sh /usr/local/bin/klav-entrypoint

# KLAV_LISTEN is not set here: the entrypoint derives it from Railway's
# PORT unless the service sets it.
# KLAV_TRUSTED_IP_HEADER is not set either: no client header is trusted
# until you check that Railway's proxy replaces X-Real-IP and set it to
# `x-real-ip` on the service (docs/self-hosting.md §8.1).
ENV KLAV_DATABASE_URL=sqlite:///data/klav.db \
    KLAV_DATA_DIR=/data \
    KLAV_LOG_FORMAT=json
EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/usr/local/bin/klav-entrypoint"]
