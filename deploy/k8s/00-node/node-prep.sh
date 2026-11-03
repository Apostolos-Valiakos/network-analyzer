#!/bin/bash
#
# Prepares a fresh Ubuntu 24.04 VM to become a single-node Kubernetes 1.33
# cluster, following the XTRUST-6G (SMTEC) cluster setup:
#   swap off, overlay + br_netfilter modules, bridge/forwarding sysctls,
#   containerd with SystemdCgroup = true, kubelet/kubeadm/kubectl 1.33 held.
# Additions for the 5G testbed: the sctp and tun modules (NGAP, F1, E2 and the
# UPF tunnel) and Docker, used only to build the images on this VM.
#
# Run once, as root:   sudo ./node-prep.sh
set -euo pipefail

K8S_MINOR="v1.33"

echo "[1/6] Swap off, now and after reboot"
swapoff -a
sed -i.bak -E '/\sswap\s/ s/^([^#])/#\1/' /etc/fstab

echo "[2/6] Kernel modules"
cat > /etc/modules-load.d/k8s.conf <<EOF
overlay
br_netfilter
sctp
tun
EOF
for m in overlay br_netfilter sctp tun; do modprobe "$m"; done

echo "[3/6] sysctls"
cat > /etc/sysctl.d/99-kubernetes-cri.conf <<EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system >/dev/null

echo "[4/6] containerd (SystemdCgroup = true) and Docker for image builds"
apt-get update
apt-get install -y apt-transport-https ca-certificates curl gpg containerd docker.io
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
# kubeadm 1.33 expects pause:3.10; an older default only causes warnings,
# but keep them aligned.
sed -i -E 's#(sandbox_image = ).*#\1"registry.k8s.io/pause:3.10"#' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd docker

echo "[5/6] Kubernetes ${K8S_MINOR} packages"
mkdir -p /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/Release.key" \
    | gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/ /" \
    > /etc/apt/sources.list.d/kubernetes.list
apt-get update
apt-get install -y 'kubelet=1.33.*' 'kubeadm=1.33.*' 'kubectl=1.33.*' 'cri-tools=1.33.*' 'kubernetes-cni=1.6.*'
apt-mark hold kubelet kubeadm kubectl
systemctl enable kubelet

echo "[6/6] Checks"
grep -q 'SystemdCgroup = true' /etc/containerd/config.toml && echo "  containerd: SystemdCgroup = true"
lsmod | grep -qw sctp && echo "  sctp module loaded"
[ -c /dev/net/tun ] && echo "  /dev/net/tun present"
swapon --show | grep -q . && echo "  WARNING: swap still on" || echo "  swap off"
kubeadm version -o short
echo "Done. Next: edit kubeadm-config.yaml, then: sudo kubeadm init --config kubeadm-config.yaml"
