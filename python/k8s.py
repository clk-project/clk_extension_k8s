#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import os
import subprocess
import grp
import json
import sys
import time
from pathlib import Path
from shlex import split

import click

from click_project.decorators import (
    argument,
    group,
    flag,
    param_config,
)
from click_project.lib import (
    call,
    move,
    download,
    extract,
    tempdir,
    temporary_file,
    cd,
    check_output,
    which,
)
from click_project.log import get_logger
from click_project.config import config


LOGGER = get_logger(__name__)


class KubeCtl:
    def call(self, arguments):
        call(["kubectl", "--context", self.context] + arguments)

    def output(self, arguments):
        return check_output(["kubectl", "--context", self.context] + arguments)


@group()
@param_config(
    "kubectl",
    "--context",
    typ=KubeCtl,
    help="The kubectl context to use",
    default="k3d-k3s-default",
)
def k8s():
    """Manipulate k8s"""


bindir = Path("~/.local/bin").expanduser()
k3d_url = (
    "https://github.com/rancher/k3d/releases/download/v4.4.4/k3d-linux-amd64"
)
helm_url = "https://get.helm.sh/helm-v3.6.0-linux-amd64.tar.gz"
kubectl_url = "https://dl.k8s.io/release/v1.21.1/bin/linux/amd64/kubectl"
tilt_url = "https://github.com/tilt-dev/tilt/releases/download/v0.21.0/tilt.0.21.0.linux.x86_64.tar.gz"
k3d_dir = os.path.expanduser("~/.k3d")

cluster_issuer = """apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: local
spec:
  ca:
    secretName: ca-key-pair
"""


@k8s.command()
def doctor():
    """Check if you have everything needed to run the stack."""
    docker = which("docker")
    if docker is None:
        raise click.UsageError("You need to install docker")
    if sys.platform == "linux":
        if "docker" not in [grp.getgrgid(g).gr_name for g in os.getgroups()]:
            raise click.UsageError(
                "You need to add the current user in the docker group"
            )
    LOGGER.info(
        "We did not find a reason to believe you will have trouble playing with the stack"
    )


@k8s.command()
@flag("--force", help="Overwrite the existing binaries")
def install_dependencies(force):
    """Install the dependencies needed to setup the stack"""
    # call(['sudo', 'apt', 'install', 'libnss-myhostname', 'docker.io'])
    if force or not which("k3d"):
        download(k3d_url, outdir=bindir, outfilename="k3d", mode=0o755)
    if force or not which("helm"):
        with tempdir() as d:
            extract(helm_url, d)
            move(Path(d) / "linux-amd64" / "helm", bindir / "helm")
            (bindir / "helm").chmod(0o755)
    if force or not which("tilt"):
        with tempdir() as d:
            extract(tilt_url, d)
            move(Path(d) / "tilt", bindir / "tilt")
    if force or not which("kubectl"):
        download(kubectl_url, outdir=bindir, outfilename="kubectl", mode=0o755)


@k8s.command(flowdepends=["k8s.install-dependencies"])
@flag("--reinstall", help="Reinstall it if it already exists")
def install_local_registry(reinstall):
    """Install the local registry"""
    if "k3d-registry.localhost" in [
        registry["name"]
        for registry in json.loads(
            check_output(split("k3d registry list -o json"))
        )
    ]:
        if reinstall:
            call(split("k3d registry delete k3d-registry.localhost"))
        else:
            LOGGER.info(
                "A registry with the name k3d-registry.localhost already exists."
                " Nothing to do."
            )
            return
    call(["k3d", "registry", "create", "registry.localhost", "-p", "5000"])


@k8s.command(flowdepends=["k8s.install-local-registry"])
@argument(
    "name", default="k3s-default", help="The name of the cluster to create"
)
def create_cluster(name):
    """Create a k3d cluster"""
    import yaml

    call(
        [
            "k3d",
            "cluster",
            "create",
            name,
            "--wait",
            "--port",
            "80:80@loadbalancer",
            "--port",
            "443:443@loadbalancer",
            "--registry-use",
            "k3d-registry.localhost:5000",
            "--k3s-agent-arg",
            "--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%",
            "--k3s-agent-arg",
            "--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%",
        ]
    )
    traefik_conf = ""
    time.sleep(10)
    while not traefik_conf:
        try:
            traefik_conf = config.kubectl.output(
                ["get", "cm", "traefik", "-n", "kube-system", "-o", "yaml"]
            )
        except subprocess.CalledProcessError:
            time.sleep(5)
    traefik_conf = yaml.load(traefik_conf, Loader=yaml.FullLoader)
    traefik_conf["data"]["traefik.toml"] = (
        "insecureSkipVerify = true\n" + traefik_conf["data"]["traefik.toml"]
    )
    with temporary_file() as f:
        f.write(yaml.dump(traefik_conf).encode("utf8"))
        f.close()
        config.kubectl.call(["apply", "-n", "kube-system", "-f", f.name])
    config.kubectl.call(
        ["delete", "pod", "-l", "app=traefik", "-n", "kube-system"]
    )


@k8s.command(flowdepends=["k8s.create-cluster"])
def install_cert_manager():
    """Install a certificate manager in the current cluster"""
    call(["helm", "repo", "add", "jetstack", "https://charts.jetstack.io"])
    call(
        [
            "helm",
            "--kube-context",
            "k3d-k3s-default",
            "upgrade",
            "--install",
            "--create-namespace",
            "--wait",
            "cert-manager",
            "jetstack/cert-manager",
            "--namespace",
            "cert-manager",
            "--version",
            "v1.2.0",
            "--set",
            "installCRDs=true",
            "--set",
            "ingressShim.defaultIssuerName=local",
            "--set",
            "ingressShim.defaultIssuerKind=ClusterIssuer",
        ]
    )
    # generate a certificate authority for the cert-manager
    with tempdir() as d, cd(d):
        call(["openssl", "genrsa", "-out", "ca.key", "2048"])
        call(
            [
                "openssl",
                "req",
                "-x509",
                "-new",
                "-nodes",
                "-key",
                "ca.key",
                "-subj",
                "/CN=localhost",
                "-days",
                "3650",
                "-reqexts",
                "v3_req",
                "-extensions",
                "v3_ca",
                "-out",
                "ca.crt",
            ]
        )
        ca_secret = config.kubectl.output(
            [
                "create",
                "secret",
                "tls",
                "ca-key-pair",
                "--cert=ca.crt",
                "--key=ca.key",
                "--namespace=cert-manager",
                "--dry-run=true",
                "-o",
                "yaml",
            ]
        )
    with temporary_file() as f:
        f.write(
            f"""{ca_secret}
---
{cluster_issuer}
""".encode(
                "utf8"
            )
        )
        f.close()
        config.kubectl.call(["apply", "-n", "cert-manager", "-f", f.name])


@k8s.command(flowdepends=["k8s.create-cluster"])
@argument("domain", help="The domain name to define")
@argument("ip", default="172.17.0.1", help="The IP address for this domain")
def add_domain(domain, ip):
    """Add a new domain entry in K8s dns"""
    import yaml

    coredns_conf = config.kubectl.output(
        ["get", "cm", "coredns", "-n", "kube-system", "-o", "yaml"]
    )
    coredns_conf = yaml.load(coredns_conf, Loader=yaml.FullLoader)
    data = f"{ip} {domain}"
    if data not in coredns_conf["data"]["NodeHosts"].split("\n"):
        coredns_conf["data"]["NodeHosts"] = (
            data + "\n" + coredns_conf["data"]["NodeHosts"]
        )
        with temporary_file() as f:
            f.write(yaml.dump(coredns_conf).encode("utf8"))
            f.close()
            config.kubectl.call(["apply", "-n", "kube-system", "-f", f.name])


@k8s.command()
def ipython():
    import IPython

    dict_ = globals()
    dict_.update(locals())
    IPython.start_ipython(argv=[], user_ns=dict_)
