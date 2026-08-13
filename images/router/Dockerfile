# Twinet router: FRR plus the tools students need at a shell prompt.
#
# Deliberately absent, compared with the platform this replaces:
#   - no sshd. Access goes through the Twinet gateway, which authenticates and
#     authorises centrally and then execs into the container. Running a daemon
#     that listens for logins in every one of a thousand routers is both a
#     security surface and a process budget we do not need.
#   - no supervisord. FRR ships its own init script and the container's PID 1 is
#     docker-init, so a process supervisor adds a layer for nothing.
#   - no looking-glass loop and no VPN observer. Those poll from the control
#     plane instead of running a background process per container, which is what
#     made the legacy platform's routers heavy and its process limits fragile.
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
        frr=~10.0 frr-rpki=~10.0 \
        iproute2 iproute2-tc iptables ip6tables \
        iputils bind-tools traceroute mtr tcpdump \
        bash curl jq wireguard-tools openssl \
        ethtool socat nftables \
    && install -m 0755 -o frr -g frr -d /var/log/frr /var/run/frr \
    && install -m 0775 -o frr -g frrvty -d /etc/frr \
    && install -m 0640 -o frr -g frrvty /dev/null /etc/frr/vtysh.conf \
    && install -m 0640 -o frr -g frr /dev/null /etc/frr/frr.conf \
    && mkdir -p /etc/twinet

# vtysh reads this to know which daemons to talk to.
RUN printf 'service integrated-vtysh-config\n' > /etc/frr/vtysh.conf \
    && chown frr:frrvty /etc/frr/vtysh.conf

COPY entrypoint.sh /usr/local/bin/twinet-entrypoint
COPY twinet_motd /etc/twinet/motd
# The address server runs on the gateway, not in a service container of its
# own: a client's first packet is a broadcast, and a server one hop away never
# hears it -- which would give every fault about DHCP the same symptom.
COPY twinet-dhcpd /usr/local/bin/twinet-dhcpd
RUN chmod 0755 /usr/local/bin/twinet-entrypoint /usr/local/bin/twinet-dhcpd

LABEL org.opencontainers.image.title="twinet-router" \
      org.opencontainers.image.description="FRR router for the Twinet teaching platform" \
      org.opencontainers.image.source="https://github.com/HongyuHe/Twinet"

ENTRYPOINT ["/usr/local/bin/twinet-entrypoint"]
CMD ["sleep", "infinity"]
