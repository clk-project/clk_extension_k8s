#!/bin/bash
set -o errexit # -e
set -o errtrace # -E
set -o nounset # -u
set -o pipefail
shopt -s inherit_errexit
set -x

# ctrl-c
trap "exit 2" SIGINT
trap "exit 3" SIGQUIT

TMP=/tmp/out
mkdir -p "${TMP}"

show_context () {
    {
        kubectl get -A networkpolicies.networking.k8s.io
        kubectl get -A pods
        kubectl describe -A pods
    } | tee "${TMP}/context"
}

fail () {
    touch "${TMP}/fail"
    if test "${directfail}" = "yes"
    then
        exit 1
    else
        exit 0
    fi
}

clk k8s cert-manager install-local-certificate --client ca-certificates --flow

if echo | openssl s_client -showcerts -connect hello.localtest.me:443 2>/dev/null | grep -q "Kubernetes Ingress Controller Fake Certificate"
then
    echo "Cert-manager did not work, I still see the fake one from the ingress"
    show_context
    fail
fi

if ! helm upgrade --install app hello --wait
then
    show_context
fi
# wait a bit for the network policy to be ready
sleep 5

http https://hello.localtest.me/ > "${TMP}/out"
if ! grep -q 'Welcome to nginx' "${TMP}/out"
then
    echo "Failed to connect to the example"
    cat "${TMP}/out"
    show_context
    fail
fi

kubectl delete --wait networkpolicies.networking.k8s.io ingress-to-app-hello
http https://hello.localtest.me/ > "${TMP}/out"
if ! grep -q '502 Bad Gateway\|504 Gateway Time-out' "${TMP}/out"
then
    echo "Removing the network policy did not block the connection"
    cat "${TMP}/out"
    show_context
    fail
fi

helm upgrade --install app hello --wait
http https://hello.localtest.me/ > "${TMP}/out"
if ! grep -q 'Welcome to nginx' "${TMP}/out"
then
    echo "Putting back the network policy did not restore the connection"
    cat "${TMP}/out"
    show_context
    fail
fi

helm upgrade --install app hello --wait
http https://hello.localtest.me/somepath/somefile > "${TMP}/out"
if test "$(cat "${TMP}/out")" != "somecontent"
then
    echo "The content of the config map is not correct before running the test of reloader"
    cat "${TMP}/out"
    show_context
    fail
fi

sed -i 's/somefile: somecontent/somefile: someothercontent/' hello/templates/configmap.yaml
helm upgrade --install app hello --wait
http https://hello.localtest.me/somepath/somefile > "${TMP}/out"
if test "$(cat "${TMP}/out")" != "someothercontent"
then
    echo "The content of the config map is not correct after running the test of reloader"
    cat "${TMP}/out"
    show_context
    fail
fi
