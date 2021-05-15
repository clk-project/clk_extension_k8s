#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import os
from pathlib import Path

from click_project.decorators import (
    argument,
    group,
)
from click_project.lib import (
    call,
    move,
    download,
    extract,
    tempdir,
    temporary_file,
)
from click_project.log import get_logger


LOGGER = get_logger(__name__)


@group()
def k8s():
    """Manipulate k8s"""


bindir = Path("~/.local/bin").expanduser()
k3d_url = "https://github.com/rancher/k3d/releases/download/v4.4.2/k3d-linux-amd64"
helm_url = "https://get.helm.sh/helm-v3.5.4-linux-amd64.tar.gz"
kubectl_url = "https://dl.k8s.io/release/v1.21.0/bin/linux/amd64/kubectl"
tilt_url = "https://github.com/tilt-dev/tilt/releases/download/v0.19.6/tilt.0.19.6.linux.x86_64.tar.gz"
k3d_dir = os.path.expanduser('~/.k3d')

cluster_issuer = """apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: local
spec:
  selfSigned: {}
"""


@k8s.command()
def install_dependencies():
    """Install the dependencies needed to setup the stack"""
    # call(['sudo', 'apt', 'install', 'libnss-myhostname', 'docker.io'])
    download(k3d_url, outdir=bindir, outfilename="k3d", mode=0o755)
    with tempdir() as d:
        extract(helm_url, d)
        move(Path(d) / "linux-amd64" / "helm", bindir / "helm")
        (bindir / "helm").chmod(0o755)
    with tempdir() as d:
        extract(tilt_url, d)
        move(Path(d) / "tilt", bindir / "tilt")
    download(kubectl_url, outdir=bindir, outfilename="kubectl", mode=0o755)


@k8s.command(flowdepends=["k8s.install-dependencies"])
def install_local_registry():
    """Install the local registry """
    call(['k3d', 'registry', 'create', 'registry.localhost', '-p', '5000'])


@k8s.command(flowdepends=["k8s.install-local-registry"])
@argument("name", default="k3s-default", help="The name of the cluster to create")
def create_cluster(name):
    """Create a k3d cluster"""
    call(['k3d', 'cluster', 'create', name,
          '--wait',
          '--port', '80:80@loadbalancer',
          '--port', '443:443@loadbalancer',
          '--registry-use', 'k3d-registry.localhost:5000',
    ])


@k8s.command(flowdepends=["k8s.create-cluster"])
def install_cert_manager():
    """Install a certificate manager in the current cluster"""
    call(["helm", "repo", "add", "jetstack", "https://charts.jetstack.io"])
    call(['helm', 'upgrade', '--install', '--create-namespace', '--wait',
          'cert-manager', 'jetstack/cert-manager',
          '--namespace', 'cert-manager',
          '--version', 'v1.2.0',
          '--set', 'installCRDs=true',
          '--set', 'ingressShim.defaultIssuerName=local',
          '--set', 'ingressShim.defaultIssuerKind=ClusterIssuer'])
    with temporary_file() as f:
        f.write(cluster_issuer.encode('utf8'))
        f.close()
        call(['kubectl', 'apply', '-n', 'cert-manager', '-f', f.name])
