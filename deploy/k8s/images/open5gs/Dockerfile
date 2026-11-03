# Open5GS 5G core, built from source at the version the testbed runs today.
# One image for every network function; each pod picks its daemon in `command`.
#
# Build (context = deploy/k8s/images):
#   docker build -f open5gs/Dockerfile -t open5gs:2.7.6 .
FROM ubuntu:22.04

ARG OPEN5GS_VERSION=v2.7.6
ENV DEBIAN_FRONTEND=noninteractive

# Build dependencies from the Open5GS "Building from source" guide, plus the
# runtime tools the UPF needs for its tunnel and NAT (iproute2, iptables) and
# envsubst (gettext-base) for render.sh.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-pip python3-setuptools python3-wheel ninja-build build-essential \
        flex bison git cmake meson pkg-config ca-certificates \
        libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn-dev \
        libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev \
        libcurl4-gnutls-dev libtins-dev libtalloc-dev \
        iproute2 iptables procps iputils-ping gettext-base \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${OPEN5GS_VERSION}" https://github.com/open5gs/open5gs /src/open5gs \
    && cd /src/open5gs \
    && meson build --prefix=/usr/local \
    && ninja -C build install \
    && ldconfig \
    && rm -rf /src/open5gs

COPY common/render.sh /usr/local/bin/render.sh
RUN chmod +x /usr/local/bin/render.sh
