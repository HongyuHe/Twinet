FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables iputils-ping tcpdump procps python3 ca-certificates \
    strongswan-charon strongswan-swanctl libstrongswan-standard-plugins libcharon-extra-plugins \
    && rm -rf /var/lib/apt/lists/*
RUN printf 'charon {\n install_routes = no\n load_modular = no\n load = random nonce x509 revocation constraints pubkey pem pkcs1 pkcs8 openssl gmp hmac sha2 kdf kernel-netlink socket-default vici\n}\n' > /etc/strongswan.conf
CMD ["sleep", "infinity"]
