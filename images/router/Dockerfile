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
FROM alpine:3.20

ARG FRR_VERSION=10.2.1-r0

RUN apk add --no-cache \
        frr frr-rpki \
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
COPY twinet-motd /etc/twinet/motd
RUN chmod 0755 /usr/local/bin/twinet-entrypoint

LABEL org.opencontainers.image.title="twinet-router" \
      org.opencontainers.image.description="FRR router for the Twinet teaching platform" \
      org.opencontainers.image.source="https://github.com/HongyuHe/Twinet"

ENTRYPOINT ["/usr/local/bin/twinet-entrypoint"]
CMD ["sleep", "infinity"]
