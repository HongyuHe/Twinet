# Twinet host: a plain Linux endpoint with the tools the assignments use.
FROM alpine:3.20

RUN apk add --no-cache \
        iproute2 iproute2-tc iptables ip6tables \
        iputils bind-tools traceroute mtr tcpdump \
        bash curl jq openssl socat netcat-openbsd \
        ethtool iperf3 \
    && mkdir -p /etc/twinet

COPY entrypoint.sh /usr/local/bin/twinet-entrypoint
RUN chmod 0755 /usr/local/bin/twinet-entrypoint

LABEL org.opencontainers.image.title="twinet-host" \
      org.opencontainers.image.source="https://github.com/HongyuHe/Twinet"

ENTRYPOINT ["/usr/local/bin/twinet-entrypoint"]
CMD ["sleep", "infinity"]
