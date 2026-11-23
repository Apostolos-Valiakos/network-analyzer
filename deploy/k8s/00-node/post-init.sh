#!/bin/bash
#
# Run as your normal user right after `sudo kubeadm init` succeeds:
#   ./post-init.sh
# Sets up kubectl, installs Cilium 1.18.1 (as on the XTRUST-6G cluster, with
# SCTP enabled for NGAP, F1 and E2), lets pods run on this single node,
# installs a default StorageClass, and labels the node like SMTEC does.
set -euo pipefail

CILIUM_VERSION="1.18.1"
LOCAL_PATH_VERSION="v0.0.30"
NODE_LABEL_VALUE="${NODE_LABEL_VALUE:-penm}"   # xtrust6g-node=<team>

echo "[1/6] kubectl for $(id -un)"
mkdir -p "$HOME/.kube"
sudo cp /etc/kubernetes/admin.conf "$HOME/.kube/config"
sudo chown "$(id -u):$(id -g)" "$HOME/.kube/config"

echo "[2/6] Cilium CLI"
if ! command -v cilium >/dev/null; then
    CLI_VERSION=$(curl -fsSL https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
    curl -fsSL --remote-name-all \
        "https://github.com/cilium/cilium-cli/releases/download/${CLI_VERSION}/cilium-linux-amd64.tar.gz"{,.sha256sum}
    sha256sum --check cilium-linux-amd64.tar.gz.sha256sum
    sudo tar xzf cilium-linux-amd64.tar.gz -C /usr/local/bin
    rm cilium-linux-amd64.tar.gz{,.sha256sum}
fi

echo "[3/6] Cilium ${CILIUM_VERSION}"
# ipam.mode=kubernetes uses kubeadm's podSubnet (10.244.0.0/16).
# kube-proxy stays, as on the XTRUST-6G cluster.
cilium install --version "${CILIUM_VERSION}" \
    --set ipam.mode=kubernetes \
    --set sctp.enabled=true
cilium status --wait

echo "[4/6] Single node: allow ordinary pods on the control-plane node"
kubectl taint nodes --all node-role.kubernetes.io/control-plane- || true

echo "[5/6] Default StorageClass (local-path-provisioner ${LOCAL_PATH_VERSION})"
kubectl apply -f "https://raw.githubusercontent.com/rancher/local-path-provisioner/${LOCAL_PATH_VERSION}/deploy/local-path-storage.yaml"
kubectl patch storageclass local-path \
    -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

echo "[6/6] Node label xtrust6g-node=${NODE_LABEL_VALUE}"
kubectl label node --all "xtrust6g-node=${NODE_LABEL_VALUE}" --overwrite

kubectl get nodes -L xtrust6g-node
echo "Done. Next: kubectl apply -f ../01-cluster/"
