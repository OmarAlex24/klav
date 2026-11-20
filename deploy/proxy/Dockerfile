# syntax=docker/dockerfile:1
#
# Image of klav-proxy, Klav's credential proxy (ADR 0036). Use and options:
# docs/self-hosting.md, "Credential proxy". Built from the repository root:
#   docker build -f deploy/proxy/Dockerfile -t klav-proxy .
#
# The proxy's own listener is only 127.0.0.1 inside the container, so
# publishing that port does not expose it. Sandboxes reach the proxy
# through the pinned channel instead (`serve --channel HOST:PORT`, ADR
# 0036 §6), where `klav-forward` in each sandbox connects: publish that
# port only as docs/self-hosting.md §9.2 says. Its key lives in a 0600
# file in /data, never in an environment variable: the proxy refuses to
# start with KLAV_AGENT_KEY set.
#
# Its memory (ADR 0044 §3): the proxy turns core dumps off and, on Linux,
# makes itself not dumpable, whatever the runtime sets. Locking its memory
# out of swap (on fault: each page once touched) needs an unlimited memlock
# limit, which an image can't set: the runtime must (`--ulimit
# memlock=-1:-1` with docker run, `init` included; `ulimits: memlock: -1`
# in deploy/proxy/compose.yaml; `LimitMEMLOCK=infinity` under systemd). On
# a rootless engine leave the memlock option out: the container doesn't
# start with it (docs/self-hosting.md §9.2).
# Without it the proxy starts unlocked, logs a warning with why, and
# `klav-proxy status` shows `locked: false`; KLAV_PROXY_REQUIRE_MEMORY_LOCK=1
# makes that start fail instead, and KLAV_PROXY_MEMORY_LOCK=off starts
# without trying. Locked, every page it touches stays resident: under
# `--memory` the kernel kills it at the cap instead of reclaiming them
# (docs/self-hosting.md §9.2, "Antes de actualizar un proxy que ya corre").
#
# The build stage is the root Dockerfile's with `-p klav-proxy`, including
# the optional sccache stage CI turns on (`--build-arg KLAV_SCCACHE=on`
# plus the ci-cache secrets): the crates both binaries share then come from
# the same cache. Without them it is plain cargo. Base images pinned by
# digest, the same as the root Dockerfile; bump them in all three files.

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

FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
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
    cargo build --release --locked -p klav-proxy \
    && cp target/release/klav-proxy /usr/local/bin/klav-proxy \
    && if [ -n "${RUSTC_WRAPPER:-}" ]; then \
        "$RUSTC_WRAPPER" --show-stats || true; \
        "$RUSTC_WRAPPER" --stop-server >/dev/null 2>&1 || true; \
    fi \
    && rm -rf /tmp/sccache

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
# ca-certificates: the proxy checks each provider's certificate against the
# system roots, and refuses to start when there are none.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 klav \
    && useradd --system --uid 10001 --gid klav --no-create-home --shell /usr/sbin/nologin klav \
    && mkdir /data \
    && chown klav:klav /data \
    && chmod 700 /data
COPY --from=build /usr/local/bin/klav-proxy /usr/local/bin/klav-proxy

ENV KLAV_HOME=/data \
    KLAV_LOG_FORMAT=json
USER klav:klav
VOLUME ["/data"]
ENTRYPOINT ["klav-proxy"]
CMD ["serve"]
