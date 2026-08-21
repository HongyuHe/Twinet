# Twinet BMv2 P4 data plane.
#
# The upstream BMv2 image is pinned by digest. A tag is retained solely as a
# human-readable release hint; the digest is what makes a program load and CLI
# behaviour reproducible.
FROM docker.io/p4lang/p4c:1.2.5.16@sha256:25d2e5366f8a7ce22c6578b264ba8b25c7a95fb3dc0690b79e4a89fbec37cc85 AS compiler

FROM docker.io/p4lang/behavioral-model:latest-24@sha256:3751094ec499b6f9227fd02db89b49a05419e39aaa4078bcb99937308d69e64a

USER root
RUN mkdir -p /etc/twinet/p4 /var/log/twinet \
    && (command -v ip >/dev/null 2>&1 || (apt-get update && apt-get install -y --no-install-recommends iproute2 netcat-openbsd && rm -rf /var/lib/apt/lists/*))

# Keep compiler and BMv2 runtime in the same pinned Ubuntu release family.
# Copying the compiler's include tree is required: a source program includes
# core.p4 and v1model.p4, so a binary alone would turn valid pipeline loading
# into a late, opaque deployment failure.
COPY --from=compiler /usr/local/bin/p4c /usr/local/bin/p4c-bm2-ss /usr/local/bin/
COPY --from=compiler /usr/local/share/p4c /usr/local/share/p4c
COPY --from=compiler /lib/x86_64-linux-gnu/libboost_iostreams.so.1.83.0 /lib/x86_64-linux-gnu/

LABEL org.opencontainers.image.title="twinet-p4-bmv2" \
      org.opencontainers.image.source="https://github.com/HongyuHe/Twinet" \
      org.opencontainers.image.description="Pinned BMv2 simple_switch runtime for typed Twinet P4 devices"

CMD ["sleep", "infinity"]
