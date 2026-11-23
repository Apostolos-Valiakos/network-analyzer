#!/bin/bash
#
# Builds every image on the VM with Docker and loads it into containerd's
# Kubernetes namespace, so pods start without a registry.
#
#   VM_IP=10.16.0.90 ./build-images.sh            # all images
#   VM_IP=10.16.0.90 ./build-images.sh flexric    # only the ones named
#
# FlexRIC's E2AP/KPM versions must match the current RIC build:
#   E2AP_VERSION=E2AP_V2 KPM_VERSION=KPM_V2_03 ./build-images.sh flexric
# (read them with: grep -E "E2AP_VERSION|KPM_VERSION" ~/flexric/build/CMakeCache.txt
#  on the current RIC machine)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IMAGES="$REPO/deploy/k8s/images"
VM_IP="${VM_IP:?set VM_IP to the VM address the browser uses, e.g. VM_IP=10.16.0.90}"
E2AP_VERSION="${E2AP_VERSION:-E2AP_V2}"
KPM_VERSION="${KPM_VERSION:-KPM_V2_03}"

load() {  # docker image -> containerd k8s.io namespace
    echo "== loading $1 into containerd"
    sudo docker save "$1" | sudo ctr -n k8s.io images import -
}

build() {
    case "$1" in
        open5gs)
            sudo docker build -f "$IMAGES/open5gs/Dockerfile" -t open5gs:2.7.6 "$IMAGES"
            load open5gs:2.7.6 ;;
        open5gs-webui)
            sudo docker build -f "$IMAGES/open5gs-webui/Dockerfile" -t open5gs-webui:2.7.6 "$IMAGES"
            load open5gs-webui:2.7.6 ;;
        srsran-cu)
            sudo docker build -f "$IMAGES/srsran/Dockerfile" \
                --build-arg SRSRAN_COMMIT=4bf1543936 --build-arg TARGET=srscu \
                -t srsran-cu:25.10 "$IMAGES"
            load srsran-cu:25.10 ;;
        srsran-du)
            sudo docker build -f "$IMAGES/srsran/Dockerfile" \
                --build-arg SRSRAN_COMMIT=9d5dd742a7 --build-arg TARGET=srsdu \
                -t srsran-du:24.10 "$IMAGES"
            load srsran-du:24.10 ;;
        flexric)
            sudo docker build -f "$IMAGES/flexric/Dockerfile" \
                --build-arg E2AP_VERSION="$E2AP_VERSION" --build-arg KPM_VERSION="$KPM_VERSION" \
                -t flexric:7365081 "$IMAGES"
            load flexric:7365081 ;;
        penm-backend)
            sudo docker build -t penm-backend:local "$REPO/server"
            load penm-backend:local ;;
        penm-frontend)
            # The Nuxt bundle has these addresses built in.
            sudo docker build \
                --build-arg API_BASE_URL="http://$VM_IP:30555" \
                --build-arg WS_URL="ws://$VM_IP:5002" \
                -t penm-frontend:local "$REPO"
            load penm-frontend:local ;;
        penm-sensor)
            sudo docker build -f "$IMAGES/sensor/Dockerfile" -t penm-sensor:local "$REPO"
            load penm-sensor:local ;;
        *)
            echo "unknown image: $1" >&2
            exit 1 ;;
    esac
}

ALL="open5gs open5gs-webui flexric srsran-cu srsran-du penm-backend penm-frontend penm-sensor"
for name in ${*:-$ALL}; do
    echo "==================== $name"
    build "$name"
done
sudo crictl images | grep -E 'open5gs|srsran|flexric|penm' || true
