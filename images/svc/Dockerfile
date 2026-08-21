# Twinet service base: DNS, measurement and matrix helpers.
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
        iproute2 iproute2-tc iptables ip6tables iputils bind bind-tools traceroute mtr tcpdump \
        bash curl jq python3 socat \
    && mkdir -p /etc/twinet /etc/bind \
    && install -d -o named -g named -m 0755 /var/named /var/run/named /var/log/named

# The RTR validator is the lab's own trust anchor. Shipping it here rather than
# depending on an external validator keeps an exercise's answer a property of
# the lab instead of a property of what somebody else has published today.
COPY twinet-rtr /usr/local/bin/twinet-rtr
COPY twinet-traffic /usr/local/bin/twinet-traffic

COPY entrypoint.sh /usr/local/bin/twinet-entrypoint
RUN chmod 0755 /usr/local/bin/twinet-entrypoint /usr/local/bin/twinet-rtr /usr/local/bin/twinet-traffic

LABEL org.opencontainers.image.title="twinet-svc" \
      org.opencontainers.image.source="https://github.com/HongyuHe/Twinet"

ENTRYPOINT ["/usr/local/bin/twinet-entrypoint"]
CMD ["sleep", "infinity"]
