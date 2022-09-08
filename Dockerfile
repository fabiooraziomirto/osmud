FROM openwrtorg/rootfs:x86_64
ARG BUILD_DATE
LABEL build-date=$BUILD_DATE
LABEL author="Luca Mannella"

## Non so bene perché ma serve
RUN mkdir -p /var/lock/
RUN touch /var/lock/opkg.lock

### Installing some useful packages
RUN opkg update
RUN opkg install git-http
# opkg install make
# opkg install gcc
RUN opkg install nano
RUN opkg install curl
RUN opkg install diffutils
RUN opkg install tcpdump
RUN opkg install luci

# Without this library osMUD does not work
RUN curl -o /tmp/libjson-c2_0.12.1-3.1_x86_64.ipk https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/libjson-c2_0.12.1-3.1_x86_64.ipk
RUN opkg install /tmp/libjson-c2_0.12.1-3.1_x86_64.ipk

# INSTALLING dnsmasq and osMUD
RUN opkg remove dnsmasq
COPY ipk/dnsmasq_2.86-1_x86_64.ipk /tmp/
RUN opkg install /tmp/dnsmasq_2.86-1_x86_64.ipk

COPY ipk/osmud_0.2.0-1_x86_64.ipk /tmp/
RUN opkg install /tmp/osmud_0.2.0-1_x86_64.ipk

# Adding Let's Encrypt certificates
RUN curl -o /tmp/lets-encrypt-x3-cross-signed.crt https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt
RUN cat /tmp/lets-encrypt-x3-cross-signed.crt >> /etc/ssl/certs/ca-certificates.crt

RUN curl -o /tmp/lets-encrypt-r3.crt https://letsencrypt.org/certs/lets-encrypt-r3.pem
RUN cat /tmp/lets-encrypt-r3.crt >> /etc/ssl/certs/ca-certificates.crt

# Adding HAss-certificate
COPY certificati/HAss-MUD-cert.pem /tmp/
RUN cat /tmp/HAss-MUD-cert.pem >> /etc/ssl/certs/ca-certificates.crt

# Opening a shell
CMD ["/bin/sh"]
