# FlexRIC near-RT RIC at the commit the testbed runs today (branch br-flexric).
#
# The E2AP and KPM versions are compile-time choices and must match what the
# srsRAN E2 agents speak. Copy them from the current RIC machine before
# building:
#   grep -E "E2AP_VERSION|KPM_VERSION" ~/flexric/build/CMakeCache.txt
# and pass them as --build-arg E2AP_VERSION=... --build-arg KPM_VERSION=...
#
# Build (context = deploy/k8s/images):
#   docker build -f flexric/Dockerfile -t flexric:7365081 .
FROM ubuntu:22.04

ARG FLEXRIC_COMMIT=736508123fe4b5dc3db83fb5baf5f0a8e9b04fe8
ARG E2AP_VERSION=E2AP_V2
ARG KPM_VERSION=KPM_V2_03
ENV DEBIAN_FRONTEND=noninteractive

# pkg-config: cmake uses it to find libraries. libmysqlclient-dev: the C xApp
# code is built with its default MySQL database support (MYSQL_XAPP).
# libconfig-dev: FlexRIC reads its .conf files with libconfig.
# gcc-12/g++-12: Ubuntu 22.04's default gcc 11 crashes (internal compiler
# error) on src/sm/mac_sm/dec/mac_dec_generic.h.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates libsctp-dev gettext-base iproute2 \
        pkg-config libmysqlclient-dev libconfig-dev gcc-12 g++-12 \
    && rm -rf /var/lib/apt/lists/*

# XAPP_MULTILANGUAGE=OFF skips the SWIG/Python xApp bindings: no xApps run in
# this testbed yet.
RUN git clone https://gitlab.eurecom.fr/mosaic5g/flexric.git /src/flexric \
    && cd /src/flexric && git checkout "${FLEXRIC_COMMIT}" \
    && mkdir build && cd build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release -DXAPP_MULTILANGUAGE=OFF \
        -DCMAKE_C_COMPILER=gcc-12 -DCMAKE_CXX_COMPILER=g++-12 \
        -DE2AP_VERSION="${E2AP_VERSION}" -DKPM_VERSION="${KPM_VERSION}" \
    && make -j"$(nproc)" \
    && make install \
    && install -m 0755 examples/ric/nearRT-RIC /usr/local/bin/nearRT-RIC \
    && rm -rf /src/flexric

COPY common/render.sh /usr/local/bin/render.sh
RUN chmod +x /usr/local/bin/render.sh
