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
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS vtysh-build

# Only vtysh uses the private FRR library; the packaged routing daemons retain
# their original libraries. The source archive matches Alpine's FRR package.
RUN apk add --no-cache build-base autoconf automake bison flex libtool \
        json-c-dev readline-dev libcap-dev 'libyang-dev<2.2' c-ares-dev \
        python3-dev elfutils-dev bsd-compat-headers linux-headers \
        net-snmp-dev rtrlib-dev protobuf-c-dev texinfo curl patchelf
WORKDIR /src
RUN curl -fsSL https://github.com/FRRouting/frr/archive/refs/tags/frr-10.0.tar.gz -o frr.tar.gz \
    && echo 'f02fe672d3ab7382752f83a8ae1e6198e6b906b4ad31063aad18b803c8756b40fa1f280c5dafe872dea505bcc882fbb8392802411f9fac0ab0bd45dac8b3ed28  frr.tar.gz' | sha512sum -c - \
    && tar xzf frr.tar.gz
WORKDIR /src/frr-frr-10.0
COPY collection/vtysh-collection.h vtysh/twinet-collection.h
COPY collection/patch.py /src/patch.py
RUN python3 /src/patch.py && ./bootstrap.sh \
    && ./configure --prefix=/usr --localstatedir=/run/frr --sbindir=/usr/lib/frr \
        --sysconfdir=/etc/frr --libdir=/usr/lib/twinet/frr --with-moduledir=/usr/lib/frr/modules \
        --disable-dependency-tracking --enable-rpki --with-libpam --disable-doc \
        --enable-snmp --enable-fpm --disable-protobuf --disable-zeromq \
        --enable-ospfapi --enable-bgp-vnc --enable-multipath=256 \
        --enable-user=frr --enable-group=frr --enable-vty-group=frrvty \
        --enable-configfile-mask=0640 --enable-logfile-mask=0640 \
    && make -j8 vtysh/vtysh \
    && patchelf --set-rpath /usr/lib/twinet/frr vtysh/.libs/vtysh \
    && mkdir -p /out/lib \
    && cp vtysh/.libs/vtysh /out/vtysh \
    && cp -a lib/.libs/libfrr.so.0* /out/lib/ \
    && strip /out/vtysh /out/lib/libfrr.so.0.0.0

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache \
        frr=~10.0 frr-rpki=~10.0 frr-pythontools=~10.0 \
        iproute2 iproute2-tc iptables ip6tables \
        iputils bind-tools traceroute mtr tcpdump \
        bash curl jq wireguard-tools openssl \
        ethtool socat nftables \
    && install -m 0755 -o frr -g frr -d /var/log/frr /var/run/frr \
    && install -m 0755 -d /lib/frr \
    && install -m 0775 -o frr -g frrvty -d /etc/frr \
    && install -m 0640 -o frr -g frrvty /dev/null /etc/frr/vtysh.conf \
    && install -m 0640 -o frr -g frr /dev/null /etc/frr/frr.conf \
    && mkdir -p /etc/twinet

COPY --from=vtysh-build /out/vtysh /usr/bin/vtysh
COPY --from=vtysh-build /out/lib/ /usr/lib/twinet/frr/

# vtysh reads this to know which daemons to talk to.
RUN printf 'service integrated-vtysh-config\n' > /etc/frr/vtysh.conf \
    && chown frr:frrvty /etc/frr/vtysh.conf

COPY entrypoint.sh /usr/local/bin/twinet-entrypoint
COPY twinet_motd /etc/twinet/motd
# The address server runs on the gateway, not in a service container of its
# own: a client's first packet is a broadcast, and a server one hop away never
# hears it -- which would give every fault about DHCP the same symptom.
COPY twinet-dhcpd /usr/local/bin/twinet-dhcpd
COPY twinet-mcast /usr/local/bin/twinet-mcast
RUN chmod 0755 /usr/local/bin/twinet-entrypoint /usr/local/bin/twinet-dhcpd \
        /usr/local/bin/twinet-mcast

LABEL org.opencontainers.image.title="twinet-router" \
      org.opencontainers.image.description="FRR router for the Twinet teaching platform" \
      org.opencontainers.image.source="https://github.com/HongyuHe/Twinet"

ENTRYPOINT ["/usr/local/bin/twinet-entrypoint"]
CMD ["sleep", "infinity"]
