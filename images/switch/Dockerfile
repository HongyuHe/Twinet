# Twinet switch: Open vSwitch, self-contained inside the container.
#
# The legacy platform required ovs-vsctl on the *host* and created host bridges,
# which meant the operator's machine had to carry OVS and every lab shared one
# OVS database. Here each switch is a real, isolated device, which is also what
# the course wants students to reason about.
# Reproducibility: the base image is pinned by digest and the packages that
# determine grading behaviour are pinned by version.
#
# A mark is only defensible if it can be reproduced, and "alpine:3.20" plus
# "apk add frr" is not a build, it is a request for whatever exists that day.
# A rebuild months later can move FRR by a minor version, change a JSON field a
# check parses, and silently regrade a class differently from the first run --
# with the image tag, the manifest and the rubric all unchanged.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

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
