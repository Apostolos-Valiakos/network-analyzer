# srsRAN Project CU or DU, built at an exact commit with UHD for the B210.
# The testbed runs the CU at 25.10 and the DU at 24.10, so this one Dockerfile
# is built twice:
#
#   docker build -f srsran/Dockerfile --build-arg SRSRAN_COMMIT=4bf1543936 \
#       --build-arg TARGET=srscu -t srsran-cu:25.10 .
#   docker build -f srsran/Dockerfile --build-arg SRSRAN_COMMIT=9d5dd742a7 \
#       --build-arg TARGET=srsdu -t srsran-du:24.10 .
#
# (context = deploy/k8s/images). Build on the VM that will run it: the
# compiler tunes for the CPU it builds on.
FROM ubuntu:22.04

ARG SRSRAN_COMMIT
ARG TARGET
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        software-properties-common gpg-agent ca-certificates git \
        cmake make gcc g++ pkg-config \
        libfftw3-dev libmbedtls-dev libsctp-dev libyaml-cpp-dev libgtest-dev \
        gettext-base iproute2 iputils-ping \
    && add-apt-repository -y ppa:ettusresearch/uhd \
    && apt-get update && apt-get install -y --no-install-recommends libuhd-dev uhd-host \
    && rm -rf /var/lib/apt/lists/*

# B200-series FPGA/firmware images, loaded onto the B210 when the DU starts.
RUN uhd_images_downloader -t b2xx

RUN test -n "${SRSRAN_COMMIT}" && test -n "${TARGET}" \
    && git clone https://github.com/srsran/srsRAN_Project /src/srsran \
    && cd /src/srsran && git checkout "${SRSRAN_COMMIT}" \
    && mkdir build && cd build \
    && cmake .. -DENABLE_UHD=ON -DENABLE_ZEROMQ=OFF -DENABLE_WERROR=OFF \
    && make -j"$(nproc)" "${TARGET}" \
    && install -m 0755 "$(find apps -type f -name "${TARGET}" -perm -u+x | head -n 1)" /usr/local/bin/ \
    && rm -rf /src/srsran

COPY common/render.sh /usr/local/bin/render.sh
RUN chmod +x /usr/local/bin/render.sh
