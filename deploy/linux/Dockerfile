# syntax=docker/dockerfile:1
#
# The Linux binaries of a release (docs/releasing.md §6), built by
# .github/workflows/release-linux.yml and exported with
# `docker build --target export --output type=local,dest=<dir>`; no image is
# kept. Inside the same pinned rust image as the root Dockerfile: Debian 12,
# so glibc 2.36 is the floor of every binary it builds.
#
# No compile cache: a fat-LTO release build with one codegen unit gets
# nothing from one, and the build sees no token (docs/releasing.md §6).
# deploy/linux/Dockerfile.dockerignore replaces the root .dockerignore for
# this build, because the root one leaves out skill/.

# The root Dockerfile's image, digest included; raise them together.
FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build
WORKDIR /src
# What the build reads: the workspace manifests, crates/, and skill/,
# which klav-cli and klav-forward embed with include_str!.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY skill skill
# The Mac app's release settings for its helpers (scripts/macos/build-app.sh):
# stripped, fat LTO, one codegen unit. /out gets two folders: the public
# tarball's three binaries, and the sandbox binaries (not part of a release).
# glibc.txt records the newest glibc symbol version each binary needs.
#
# The commit and its committer time (Unix seconds), from the workflow's
# --build-arg: the build identity that `klav --version`, `klavd --version`,
# `klav-forward --version` and `klav-proxy --version` print
# (crates/klav-daemon/build.rs). The source here has
# no .git, so without them the binaries say "commit unknown". Declared last,
# right before the build, so the layers above stay cached across commits;
# RUN sees each ARG as an environment variable of the same name.
ARG KLAV_BUILD_COMMIT
ARG KLAV_BUILD_COMMIT_TIME
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
        -p klav-cli -p klav-daemon -p klav-forward -p klav-proxy \
        --bin klav --bin klavd --bin klav-native-host --bin klav-forward --bin klav-proxy \
        --config 'profile.release.strip="symbols"' \
        --config 'profile.release.lto="fat"' \
        --config 'profile.release.codegen-units=1' \
    && mkdir -p /out/klav-linux-x86_64 /out/sandbox \
    && cp target/release/klav target/release/klavd target/release/klav-native-host /out/klav-linux-x86_64/ \
    && cp target/release/klav-forward target/release/klav-proxy /out/sandbox/ \
    && for bin in /out/klav-linux-x86_64/* /out/sandbox/*; do \
        printf '%s %s\n' "$(basename "$bin")" \
            "$(objdump -T "$bin" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)"; \
    done > /out/glibc.txt \
    && cat /out/glibc.txt

FROM scratch AS export
COPY --from=build /out/ /
