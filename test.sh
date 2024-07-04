#!/bin/bash
set -o errexit # -e
set -o errtrace # -E
set -o nounset # -u
set -o pipefail
shopt -s inherit_errexit

# ctrl-c
trap "exit 2" SIGINT
trap "exit 3" SIGQUIT

show_context () {
    {
        kubectl get -A networkpolicies.networking.k8s.io
        kubectl get -A pods
        kubectl describe -A pods
    } | tee "${TMP}/context"
}

fail () {
    touch "${TMP}/fail"
    exit 0
}

if ! helm upgrade --install app hello --wait
then
    show_context
fi
# wait a bit for the network policy to be ready
sleep 5

TMP=/tmp/out
mkdir -p "${TMP}"

clk k8s cert-manager install-local-certificate --client ca-certificates

curl https://hello.localtest.me/ > "${TMP}/out"
if ! grep -q 'Welcome to nginx' "${TMP}/out"
then
    echo "Failed to connect to the example"
    cat "${TMP}/out"
    show_context
    fail
fi

kubectl delete --wait networkpolicies.networking.k8s.io ingress-to-app-hello
curl https://hello.localtest.me/ > "${TMP}/out"
if ! grep -q '502 Bad Gateway\|504 Gateway Time-out' "${TMP}/out"
then
    echo "Removing the network policy did not block the connection"
    cat "${TMP}/out"
    show_context
    fail
fi

helm upgrade --install app hello --wait
curl https://hello.localtest.me/ > "${TMP}/out"
if ! grep -q 'Welcome to nginx' "${TMP}/out"
then
    echo "Putting back the network policy did not restore the connection"
    cat "${TMP}/out"
    show_context
    fail
fi

helm upgrade --install app hello --wait
curl https://hello.localtest.me/somepath/somefile > "${TMP}/out"
if test "$(cat "${TMP}/out")" != "somecontent"
then
    echo "The content of the config map is not correct before running the test of reloader"
    cat "${TMP}/out"
    show_context
    fail
fi

sed -i 's/somefile: somecontent/somefile: someothercontent/' hello/templates/configmap.yaml
helm upgrade --install app hello --wait
curl https://hello.localtest.me/somepath/somefile > "${TMP}/out"
if test "$(cat "${TMP}/out")" != "someothercontent"
then
    echo "The content of the config map is not correct after running the test of reloader"
    cat "${TMP}/out"
    show_context
    fail
fi
