# ns-ci — the act_runner image this repo's CI runs in.
#
# Why this exists: `docker.gitea.com/runner-images:ubuntu-latest` is a fine base
# but has no zig, and pulling a ~47 MB zig tarball from ziglang.org on every
# push measured 50–900 KB/s from this network (6+ minutes, twice timed out at
# the 20-minute job budget).  Baking the toolchain in turns the per-push cost
# into zero and makes the run deterministic.  The workflow still installs
# anything missing, so it degrades to a plain runner instead of breaking.
#
# Build (on the host, once; ~2 min for the download):
#   docker build -t ns-ci:ubuntu-24.04 ci/runner
#
# Then give it a label in the act_runner config (`/data/config.yaml` next to
# .runner, i.e. 1panel's gitea/data/runner/config.yaml) and restart the runner:
#   labels:
#     - "ubuntu-latest:docker://docker.gitea.com/runner-images:ubuntu-latest"
#     - "ns-ci:docker://ns-ci:ubuntu-24.04"
#
# Every pin is the same one written at the top of .gitea/workflows/ci.yml;
# bump both together, never one.
FROM docker.gitea.com/runner-images:ubuntu-latest

ARG ZIG_VERSION=0.16.0
ARG ZIG_SHA256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
ARG JUST_VERSION=1.59.0
ARG JUST_SHA256=409044617b6f06517c1035e55ca38c8c856ff8b650e41bc2aa1ef82d5903a23e

# The sha256 check below, not the URL, is the thing that makes a mirror safe:
# point these at a LAN copy (and keep the digests) when ziglang.org is slow.
ARG ZIG_URL=https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz
ARG JUST_URL=https://github.com/casey/just/releases/download/${JUST_VERSION}/just-${JUST_VERSION}-x86_64-unknown-linux-musl.tar.gz

# glibc, not musl: build.zig:44-47 — QuickJS's bundled allocator misbehaves
# under musl, so `zig build test` cannot run on the `alpine` label at all.
RUN set -eux; \
    apt-get update -qq; \
    apt-get install -y -qq --no-install-recommends xz-utils python3-venv ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    curl -fsSL -o /tmp/zig.tar.xz "${ZIG_URL}"; \
    echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/zig; \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    ln -sf /opt/zig/zig /usr/local/bin/zig; \
    rm /tmp/zig.tar.xz; \
    curl -fsSL -o /tmp/just.tar.gz "${JUST_URL}"; \
    echo "${JUST_SHA256}  /tmp/just.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/just.tar.gz -C /usr/local/bin just; \
    rm /tmp/just.tar.gz; \
    zig version; just --version

# The python side the gate needs: pytest, the two pinned offline-PE decoders
# (`capstone`/`pefile` are imported at module level by the tools their tests
# cover), and psutil (windows-subpackage tests).  `unicorn` is deliberately
# absent — only scripts/emu_desc.py needs it and its artifacts are checked in.
#
# A venv, because Ubuntu 24.04 is PEP 668 "externally managed" and a bare
# `pip install` refuses by design.  Prepending it to PATH keeps `python3` (what
# the justfile recipes call) pointing at it for both the interactive shell and
# the job steps.
RUN set -eux; \
    python3 -m venv /opt/py; \
    /opt/py/bin/pip install --no-cache-dir -q \
      'pytest==8.4.2' 'capstone==5.0.7' 'pefile==2024.8.26' psutil; \
    /opt/py/bin/python -m pytest --version; \
    /opt/py/bin/python -c 'import capstone, pefile, psutil'

ENV PATH="/opt/py/bin:${PATH}"
