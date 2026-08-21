# Twinet BIRD 2 router. Both the base image and the routing daemon package are
# pinned: BIRD's command output is parsed into vendor-neutral netstate, so a
# moving package version is a grading behavior change.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache \
        bird=2.15.1-r0 \
        iproute2 iproute2-tc iptables ip6tables \
        iputils bind-tools traceroute mtr tcpdump \
        bash curl jq wireguard-tools openssl \
        ethtool socat nftables \
    && mkdir -p /etc/bird /etc/twinet /run

COPY entrypoint.sh /usr/local/bin/twinet-bird-entrypoint
COPY twinet_motd /etc/twinet/motd
RUN chmod 0755 /usr/local/bin/twinet-bird-entrypoint

LABEL org.opencontainers.image.title="twinet-bird" \
      org.opencontainers.image.description="BIRD 2 router for the Twinet teaching platform" \
      org.opencontainers.image.source="https://github.com/HongyuHe/Twinet" \
      org.opencontainers.image.version="bird-2.15.1-r0"

ENTRYPOINT ["/usr/local/bin/twinet-bird-entrypoint"]
CMD ["sleep", "infinity"]
