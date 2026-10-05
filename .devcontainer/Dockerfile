# Ostia development container: the same Debian stable environment as the CI jobs (NFR-15).
# Built from the single sources tools/dev/packages.txt (Debian packages), tools/dev/versions.env
# (uv, just, cargo-nextest, the fuzzing nightly and cargo-fuzz) and rust-toolchain.toml. Runs as root, like the CI container; start it with
# --privileged (devcontainer.json) so the disk-image tests can attach loop devices.
FROM --platform=linux/amd64 debian:13

COPY tools/dev/packages.txt tools/dev/versions.env rust-toolchain.toml /tmp/ostia/

RUN apt-get update \
    && sed -e 's/#.*//' -e '/^[[:space:]]*$/d' /tmp/ostia/packages.txt \
       | xargs apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

ENV PATH=/root/.cargo/bin:/root/.local/bin:${PATH}

RUN set -eu; . /tmp/ostia/versions.env; \
    curl --proto '=https' --tlsv1.2 -sSfo /tmp/rustup-init.sh https://sh.rustup.rs; \
    sh /tmp/rustup-init.sh -y --default-toolchain none --profile minimal; \
    cd /tmp/ostia && rustup toolchain install; \
    curl --proto '=https' --tlsv1.2 -LsSfo /tmp/uv-install.sh "https://astral.sh/uv/${UV_VERSION}/install.sh"; \
    sh /tmp/uv-install.sh; \
    uv tool install "rust-just==${JUST_VERSION}"; \
    cargo install --locked "cargo-nextest@${NEXTEST_VERSION}"; \
    rustup toolchain install "${NIGHTLY_TOOLCHAIN}" --profile minimal; \
    cargo install --locked "cargo-fuzz@${CARGO_FUZZ_VERSION}"; \
    rm -rf /tmp/rustup-init.sh /tmp/uv-install.sh /root/.cargo/registry

WORKDIR /workspaces/ostia
