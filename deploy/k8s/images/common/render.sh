#!/bin/sh
# Fills a config template with this pod's IP and the IPs of other pods, then
# runs the program. srsRAN and FlexRIC only accept IP addresses, and pod IPs
# change on every restart, so they cannot be written into the config by hand.
#
#   render.sh <template> <output> -- <command...>
#
# Environment:
#   POD_IP    this pod's IP (from the Kubernetes downward API)
#   RESOLVE   space-separated VAR=dns-name pairs, e.g.
#             "AMF_IP=open5gs-amf.team-5g.svc.cluster.local". Each name is
#             looked up (waiting until it answers) and exported as VAR.
# Only ${POD_IP} and the RESOLVE variables are substituted; any other "$" in
# the template is left alone.
set -eu

template=$1
output=$2
shift 2
[ "${1:-}" = "--" ] && shift

vars='${POD_IP}'
for pair in ${RESOLVE:-}; do
    var=${pair%%=*}
    host=${pair#*=}
    ip=""
    while [ -z "$ip" ]; do
        ip=$(getent ahostsv4 "$host" | awk 'NR == 1 { print $1 }')
        [ -n "$ip" ] || { echo "render: waiting for $host"; sleep 2; }
    done
    export "$var=$ip"
    vars="$vars \${$var}"
    echo "render: $var=$ip ($host)"
done

mkdir -p "$(dirname "$output")"
envsubst "$vars" < "$template" > "$output"
echo "render: wrote $output"
exec "$@"
