#!/bin/bash
set -o errexit # -e
set -o errtrace # -E
set -o nounset # -u
set -o pipefail
shopt -s inherit_errexit

# ctrl-c
trap "exit 2" SIGINT
trap "exit 3" SIGQUIT

clk k8s --distribution=$distribution flow --flow-after k8s.install-dependency.all
helm upgrade --install app hello --wait
# wait a bit for the network policy to be ready
sleep 5

TMP="$(mktemp -d)"
trap "rm -rf '${TMP}'" 0

curl http://hello.localtest.me/ > "${TMP}/out"
if ! grep -q 'Welcome to nginx' "${TMP}/out"
then
    echo "Failed to connect to the example"
    cat "${TMP}/out"
    exit 1
fi
