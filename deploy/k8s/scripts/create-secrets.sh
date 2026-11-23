#!/bin/bash
#
# Creates the two Secrets the manifests expect. Nothing secret is stored in git.
#
#   ./create-secrets.sh /path/to/hnet
#
# /path/to/hnet: a copy of /etc/open5gs/hnet from the current core machine
# (10.16.0.82). Those keys de-conceal SUCIs; if the TRB500's SIM conceals its
# identity (SUCI protection scheme A or B), only the original keys work.
# Without the argument, new keys are generated: enough for a SIM using the
# null scheme, which sends its IMSI in clear.
set -euo pipefail

HNET_DIR="${1:-}"

if [ -z "$HNET_DIR" ]; then
    HNET_DIR=$(mktemp -d)
    echo "No hnet folder given: generating new home-network keys in $HNET_DIR"
    for i in 1 3 5; do openssl genpkey -algorithm X25519 -out "$HNET_DIR/curve25519-$i.key"; done
    for i in 2 4 6; do openssl ecparam -name prime256v1 -genkey -conv_form compressed -out "$HNET_DIR/secp256r1-$i.key"; done
fi

kubectl -n team-5g create secret generic open5gs-hnet --from-file="$HNET_DIR" \
    --dry-run=client -o yaml | kubectl apply -f -

if kubectl -n team-penm get secret penm-secrets >/dev/null 2>&1; then
    echo "penm-secrets already exists; delete it first to regenerate"
else
    ADMIN_PASSWORD=$(openssl rand -hex 12)
    kubectl -n team-penm create secret generic penm-secrets \
        --from-literal=DB_PASSWORD="$(openssl rand -hex 24)" \
        --from-literal=JWT_SECRET_KEY="$(openssl rand -hex 32)" \
        --from-literal=SECRET_TOKEN="$(openssl rand -hex 32)" \
        --from-literal=ADMIN_USERNAME=admin \
        --from-literal=ADMIN_PASSWORD="$ADMIN_PASSWORD"
    echo "PENM admin login: admin / $ADMIN_PASSWORD   (store it; it is not shown again)"
fi
