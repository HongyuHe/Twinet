# Twinet's self-contained OpenFlow 1.3 controller. The base is pinned by
# digest, and the controller binary is built from this repository by Makefile.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache iproute2 iptables netcat-openbsd \
    && mkdir -p /etc/twinet /run/twinet /var/log

COPY twinet-openflow-controller /usr/local/bin/twinet-openflow-controller
RUN chmod 0755 /usr/local/bin/twinet-openflow-controller

LABEL org.opencontainers.image.title="twinet-openflow-controller" \
      org.opencontainers.image.source="https://github.com/HongyuHe/Twinet"

CMD ["sleep", "infinity"]
