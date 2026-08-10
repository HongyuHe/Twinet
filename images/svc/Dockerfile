# Twinet service base: DNS, measurement and matrix helpers.
FROM alpine:3.20

RUN apk add --no-cache \
        iproute2 iputils bind bind-tools traceroute mtr tcpdump \
        bash curl jq python3 socat \
    && mkdir -p /etc/twinet /var/named

COPY entrypoint.sh /usr/local/bin/twinet-entrypoint
RUN chmod 0755 /usr/local/bin/twinet-entrypoint

LABEL org.opencontainers.image.title="twinet-svc" \
      org.opencontainers.image.source="https://github.com/HongyuHe/Twinet"

ENTRYPOINT ["/usr/local/bin/twinet-entrypoint"]
CMD ["sleep", "infinity"]
