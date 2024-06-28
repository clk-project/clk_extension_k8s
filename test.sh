#!/bin/bash
set -o errexit # -e
set -o errtrace # -E
set -o nounset # -u
set -o pipefail
shopt -s inherit_errexit

# ctrl-c
trap "exit 2" SIGINT
trap "exit 3" SIGQUIT

clk_args=()
if test "${debug}" = "yes"
then
    clk_args+=(--debug)
    set -x
fi

show_context () {
    kubectl get -A networkpolicies.networking.k8s.io
    kubectl get -A pods
    kubectl describe -A pods
}

clk "${clk_args[@]}" k8s --distribution=$distribution flow --flow-after k8s.install-dependency.all
if ! helm upgrade --install app hello --wait
then
    show_context
fi
# wait a bit for the network policy to be ready
sleep 5

TMP="$(mktemp -d)"
trap "rm -rf '${TMP}'" 0


curl http://hello.localtest.me/ > "${TMP}/out"
if ! grep -q 'Welcome to nginx' "${TMP}/out"
then
    echo "Failed to connect to the example"
    cat "${TMP}/out"
    show_context
    exit 1
fi

kubectl delete --wait networkpolicies.networking.k8s.io ingress-to-app-hello
curl http://hello.localtest.me/ > "${TMP}/out"
if ! grep -q '502 Bad Gateway\|504 Gateway Time-out' "${TMP}/out"
then
    echo "Removing the network policy did not block the connection"
    cat "${TMP}/out"
    show_context
    exit 1
fi

helm upgrade --install app hello --wait
curl http://hello.localtest.me/ > "${TMP}/out"
if ! grep -q 'Welcome to nginx' "${TMP}/out"
then
    echo "Putting back the network policy did not restore the connection"
    cat "${TMP}/out"
    show_context
    exit 1
fi
