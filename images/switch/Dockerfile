# Twinet switch: Open vSwitch, self-contained inside the container.
#
# The legacy platform required ovs-vsctl on the *host* and created host bridges,
# which meant the operator's machine had to carry OVS and every lab shared one
# OVS database. Here each switch is a real, isolated device, which is also what
# the course wants students to reason about.
FROM alpine:3.20

RUN apk add --no-cache \
        openvswitch \
        iproute2 iproute2-tc iputils tcpdump \
        bash curl jq \
    && mkdir -p /var/run/openvswitch /var/log/openvswitch /etc/openvswitch /etc/twinet

COPY entrypoint.sh /usr/local/bin/twinet-entrypoint
RUN chmod 0755 /usr/local/bin/twinet-entrypoint

LABEL org.opencontainers.image.title="twinet-switch" \
      org.opencontainers.image.source="https://github.com/HongyuHe/Twinet"

ENTRYPOINT ["/usr/local/bin/twinet-entrypoint"]
CMD ["sleep", "infinity"]
