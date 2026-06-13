# syntax=docker/dockerfile:1
#
# secator-rs — Rust rewrite container.
#
# Two-stage build:
#   1. `builder` — debian:bookworm with the Rust toolchain compiles
#      `secator-cli` in release mode. We use Debian (not Alpine) because a
#      handful of workspace crates pull in C libs (libmongocrypt via
#      secator-mongo, ring/openssl via litellm-rust, etc.) that don't have a
#      first-class musl build path.
#   2. `runtime` — debian:bookworm-slim copies the binary onto a clean base
#      and runs `secator install tools --cleanup --fail-fast` so the
#      48 external CLI tools (nmap, nuclei, httpx, …) land on `PATH` exactly
#      like the Python image at `/Dockerfile` builds them.
#
# Build:
#   docker build -t secator-rs:dev -f rust/Dockerfile rust/
#   docker run --rm secator-rs:dev health      # → 48/48 tools installed
#   docker run --rm -it secator-rs:dev scan domain example.com
#
# Build args:
#   --build-arg flavor=lite    # skip the tool-install step (binary only)
#   --build-arg build_from_source=true   # force-source-install for tools

ARG RUST_VERSION=1.83
ARG RUNTIME_BASE=debian:bookworm-slim

# ---------------------------------------------------------------- 1. builder
FROM rust:${RUST_VERSION}-bookworm AS builder

# Build deps for crates with C extensions (mongodb client, openssl-sys, …).
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        cmake \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
# Copy workspace + crates. We don't try to be cute with cargo-chef caching —
# the workspace recompiles cleanly in ~2 min on a modern host.
COPY . .
RUN cargo build --release -p secator-cli
# Strip + verify the binary in one step so the runtime stage is leaner.
RUN strip target/release/secator && \
    target/release/secator --version

# ---------------------------------------------------------------- 2. runtime
FROM ${RUNTIME_BASE} AS runtime

ARG flavor=full
ARG build_from_source=false

# Runtime deps:
#   - ca-certificates: HTTPS providers (Circl, GHSA, …).
#   - sudo: for nmap/arpscan/arp the same way the Python image grants it.
#   - curl + git + gnupg: bootstrap path for `secator install tools` that pulls
#     github releases or builds from source.
#   - nmap + arp-scan: shipped via apt so the privileged sudoers entries below
#     point at real binaries on first boot. Other tools install via
#     `secator install tools` at the end.
#   - go + cargo: needed by the `secator install` path for tools whose only
#     publish channel is `go install` / `cargo install`.
#   - python3-pip + pipx: a couple of tools (h8mail, maigret, dirsearch,
#     trufflehog plugins) install via pip. Kept minimal — no pipx for secator
#     itself, just for these Python-tool dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        sudo \
        curl \
        wget \
        git \
        gnupg \
        unzip \
        flock \
        nmap \
        arp-scan \
        net-tools \
        iputils-ping \
        whois \
        dnsutils \
        golang-go \
        python3-pip \
        pipx \
    && rm -rf /var/lib/apt/lists/*

# Mirror the Python image's `secator` user setup.
RUN useradd --create-home --shell /bin/bash secator

# Privileged binaries (Python parity — same NOPASSWD entries).
RUN echo "secator ALL=(ALL) NOPASSWD: /usr/bin/nmap *" >> /etc/sudoers && \
    echo "secator ALL=(ALL) NOPASSWD: /usr/sbin/arp-scan *" >> /etc/sudoers && \
    echo "secator ALL=(ALL) NOPASSWD: /usr/sbin/arp *" >> /etc/sudoers && \
    echo "secator ALL=(ALL) NOPASSWD: /usr/bin/apt-get install *" >> /etc/sudoers && \
    echo "secator ALL=(ALL) NOPASSWD: /usr/bin/flock /tmp/install.lock apt-get install *" >> /etc/sudoers && \
    chmod 0440 /etc/sudoers

# Drop the compiled binary onto the secator user's bin dir.
COPY --from=builder /build/target/release/secator /home/secator/.local/bin/secator
RUN chown -R secator:secator /home/secator /tmp && \
    chmod +x /home/secator/.local/bin/secator

USER secator
WORKDIR /home/secator
ENV PATH="/home/secator/.local/bin:/home/secator/.local/go/bin:/home/secator/go/bin:${PATH}" \
    GOBIN="/home/secator/.local/bin" \
    GOPATH="/home/secator/go" \
    CARGO_HOME="/home/secator/.cargo" \
    TERM="xterm-256color" \
    SECATOR_SECURITY_PROMPT_SUDO_PASSWORD="0"

# Same dual-flavor logic as the Python image, adapted to the Rust CLI:
#   `flavor=full` (default) → `secator install --all --yes` pulls every tool
#       binary onto PATH (github-release or source-built or apt-installed
#       per each task's InstallSpec).
#   `flavor=lite` → ship just the secator binary; the operator can run
#       `secator install --all` later (or piecewise `secator install <task>`).
RUN if [ "$build_from_source" = "true" ]; then \
        secator config set security.force_source_install true; \
    fi && \
    if [ "$flavor" != "lite" ]; then \
        secator install --all --yes --missing-only; \
    fi

# Revoke broad apt-install permissions once the tools are in (Python parity).
USER root
RUN if [ "$flavor" != "lite" ]; then \
        sed -i '/secator ALL=(ALL) NOPASSWD: \/usr\/bin\/apt-get install \*/d' /etc/sudoers && \
        sed -i '/secator ALL=(ALL) NOPASSWD: \/usr\/bin\/flock \/tmp\/install.lock apt-get install \*/d' /etc/sudoers; \
    fi
USER secator

ENTRYPOINT ["secator"]
