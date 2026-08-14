# Twinet host: a plain Linux endpoint with the tools the assignments use.
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
        iproute2 iproute2-tc iptables ip6tables \
        iputils bind-tools traceroute mtr tcpdump \
        bash curl jq openssl socat netcat-openbsd \
        ethtool iperf3 \
    && mkdir -p /etc/twinet

COPY entrypoint.sh /usr/local/bin/twinet-entrypoint
# The multicast tool, built from this module. The advanced course's exercise
# uses smcroute to join a group and ping to send to it, which needs two packages
# and leaves a membership behind after it exits; this holds the membership in an
# open socket, so a measurement cannot change the next one's answer.
COPY twinet-mcast /usr/local/bin/twinet-mcast
RUN chmod 0755 /usr/local/bin/twinet-entrypoint /usr/local/bin/twinet-mcast

LABEL org.opencontainers.image.title="twinet-host" \
      org.opencontainers.image.source="https://github.com/HongyuHe/Twinet"

ENTRYPOINT ["/usr/local/bin/twinet-entrypoint"]
CMD ["sleep", "infinity"]
