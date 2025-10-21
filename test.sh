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

get () {
    http --ignore-stdin "$@"
}

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
clk k8s network-policy install

if ! helm upgrade --install app hello --wait
then
    show_context
fi

docheck () {
    attempts=5
    while ! check
    do
        if test "${attempts}" -gt "0"
        then
            echo "${msg}"
            attempts=$((attempts - 1))
            sleep 15
        else
            if test -e "${TMP}/out"
            then
                cat "${TMP}/out"
            fi
            show_context
            fail
        fi
    done
    rm -rf "${TMP}/out"
}

check () {
    if echo | openssl s_client -showcerts -connect hello.localtest.me:443 2>/dev/null | grep -q "Kubernetes Ingress Controller Fake Certificate"
    then
        echo "Cert-manager did not work, I still see the fake one from the ingress"
        return 1
    fi
}
msg="Waiting for the certificate to be issued"
docheck

ingress () {
    get https://hello.localtest.me/ > "${TMP}/out"
    if ! grep -q 'Welcome to nginx' "${TMP}/out"
    then
        return 1
    fi
}
msg="Waiting for the ingress to be setup"
docheck

kubectl delete --wait networkpolicies.networking.k8s.io ingress-to-app-hello

check ( ) {
    get https://hello.localtest.me/ > "${TMP}/out"
    grep -q '502 Bad Gateway\|504 Gateway Time-out' "${TMP}/out"
}
msg="Removing the network policy did not block the connection"
docheck

helm upgrade --install app hello --wait

check () {
    get https://hello.localtest.me/ > "${TMP}/out"
    grep -q 'Welcome to nginx' "${TMP}/out"
}
msg="Putting back the network policy did not restore the connection"
docheck

helm upgrade --install app hello --wait

check () {
get https://hello.localtest.me/somepath/somefile > "${TMP}/out"
test "$(cat "${TMP}/out")" = "somecontent"
}
msg="The content of the config map is not correct before running the test of reloader"
docheck

sed -i 's/somefile: somecontent/somefile: someothercontent/' hello/templates/configmap.yaml
helm upgrade --install app hello --wait

check () {
    get https://hello.localtest.me/somepath/somefile > "${TMP}/out"
    test "$(cat "${TMP}/out")" = "someothercontent"
    }
msg="The content of the config map is not correct after running the test of reloader"
docheck
