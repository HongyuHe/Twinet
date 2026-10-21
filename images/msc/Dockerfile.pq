FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev pkg-config curl ca-certificates bzip2 iproute2 iptables iputils-ping tcpdump python3 procps openssl && rm -rf /var/lib/apt/lists/*
RUN curl -fL https://download.strongswan.org/strongswan-6.1.0.tar.bz2 -o /tmp/strongswan.tar.bz2 && sha256sum /tmp/strongswan.tar.bz2 && tar -xjf /tmp/strongswan.tar.bz2 -C /tmp && cd /tmp/strongswan-6.1.0 && ./configure --prefix=/usr --sysconfdir=/etc --enable-openssl --enable-ml --enable-swanctl --enable-vici --enable-kernel-netlink --enable-socket-default --disable-stroke && make -j8 && make install && ldconfig
CMD ["sleep", "infinity"]
