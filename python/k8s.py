#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import os
import subprocess
import time
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
    cd,
    check_output,
    which,
)
from click_project.log import get_logger


LOGGER = get_logger(__name__)


@group()
def k8s():
    """Manipulate k8s"""


bindir = Path("~/.local/bin").expanduser()
kind_url = "https://kind.sigs.k8s.io/dl/v0.11.1/kind-linux-amd64"
helm_url = "https://get.helm.sh/helm-v3.6.0-linux-amd64.tar.gz"
kubectl_url = "https://dl.k8s.io/release/v1.21.1/bin/linux/amd64/kubectl"
tilt_url = "https://github.com/tilt-dev/tilt/releases/download/v0.20.7/tilt.0.20.7.linux.x86_64.tar.gz"
kind_config = """
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta2
  kind: ClusterConfiguration
  metadata:
    name: config
  apiServer:
    extraArgs:
      "feature-gates": "EphemeralContainers=true"
  scheduler:
    extraArgs:
      "feature-gates": "EphemeralContainers=true"
  controllerManager:
    extraArgs:
      "feature-gates": "EphemeralContainers=true"
- |
  apiVersion: kubeadm.k8s.io/v1beta2
  kind: InitConfiguration
  metadata:
    name: config
  nodeRegistration:
    kubeletExtraArgs:
      "feature-gates": "EphemeralContainers=true"
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
"""

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
    import grp
    if not "docker" in [
            grp.getgrgid(g).gr_name for g in os.getgroups()
    ]:
        raise click.UsageError("You need to add the current user in the docker group")
    LOGGER.info("We did not find a reason to believe you will have trouble playing with the stack")


@k8s.command()
def install_dependencies():
    """Install the dependencies needed to setup the stack"""
    # call(['sudo', 'apt', 'install', 'libnss-myhostname', 'docker.io'])
    download(kind_url, outdir=bindir, outfilename="kind", mode=0o755)
    with tempdir() as d:
        extract(helm_url, d)
        move(Path(d) / "linux-amd64" / "helm", bindir / "helm")
        (bindir / "helm").chmod(0o755)
    with tempdir() as d:
        extract(tilt_url, d)
        move(Path(d) / "tilt", bindir / "tilt")
    download(kubectl_url, outdir=bindir, outfilename="kubectl", mode=0o755)


# @k8s.command(flowdepends=["k8s.install-dependencies"])
# def install_local_registry():
#     """Install the local registry """
#     call(['k3d', 'registry', 'create', 'registry.localhost', '-p', '5000'])


@k8s.command(flowdepends=["k8s.install-dependencies"])
def create_cluster():
    """Create a kind cluster"""
    import yaml
    with temporary_file() as f:
        f.write(kind_config.encode('utf8'))
        f.close()
        call(['kind', 'create', 'cluster', '--config', f.name])


@k8s.command(flowdepends=["k8s.create-cluster"])
def install_ingress():
    """Install a ingress"""
    call(["helm", "repo", "add", "ingress-nginx", "https://kubernetes.github.io/ingress-nginx"])
    call(['kubectl', '--context', 'kind-kind', 'apply', '-f',
          'https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/provider/kind/deploy.yaml'])
    call(['kubectl', 'wait', '--namespace', 'ingress-nginx', '--for=condition=ready', 'pod',
          '--selector=app.kubernetes.io/component=controller', '--timeout=90s'])


@k8s.command(flowdepends=["k8s.install-ingress"])
def install_cert_manager():
    """Install a certificate manager in the current cluster"""
    call(["helm", "repo", "add", "jetstack", "https://charts.jetstack.io"])
    call(['helm', '--kube-context', 'kind-kind', 'upgrade', '--install', '--create-namespace', '--wait',
          'cert-manager', 'jetstack/cert-manager',
          '--namespace', 'cert-manager',
          '--version', 'v1.2.0',
          '--set', 'installCRDs=true',
          '--set', 'ingressShim.defaultIssuerName=local',
          '--set', 'ingressShim.defaultIssuerKind=ClusterIssuer'])
    # generate a certificate authority for the cert-manager
    with tempdir() as d, cd(d):
        call(['openssl', 'genrsa', '-out', 'ca.key', '2048'])
        call(['openssl', 'req',  '-x509', '-new', '-nodes', '-key', 'ca.key', '-subj', '/CN=localhost', '-days', '3650',
              '-reqexts', 'v3_req', '-extensions', 'v3_ca', '-out', 'ca.crt'])
        ca_secret = check_output(['kubectl', '--context', 'kind-kind', 'create', 'secret', 'tls', 'ca-key-pair',
                                  '--cert=ca.crt', '--key=ca.key',
                                  '--namespace=cert-manager', '--dry-run=true', '-o', 'yaml'])
    with temporary_file() as f:
        f.write(f'''{ca_secret}
---
{cluster_issuer}
'''.encode('utf8'))
        f.close()
        call(['kubectl', '--context', 'kind-kind', 'apply', '-n', 'cert-manager', '-f', f.name])


@k8s.command(flowdepends=["k8s.create-cluster"])
@argument('domain', help="The domain name to define")
@argument('ip', default="172.17.0.1", help="The IP address for this domain")
def add_domain(domain, ip):
    """Add a new domain entry in K8s dns"""
    import yaml
    coredns_conf = check_output(['kubectl', '--context', 'kind-kind', 'get', 'cm', 'coredns', '-n', 'kube-system',
                                 '-o', 'yaml'])
    coredns_conf = yaml.load(coredns_conf, Loader=yaml.FullLoader)
    data = f'{ip} {domain}'
    if data not in coredns_conf['data'].get('NodeHosts', '').split('\n'):
        coredns_conf['data']['NodeHosts'] = data + '\n' + coredns_conf['data'].get('NodeHosts', '')
        with temporary_file() as f:
            f.write(yaml.dump(coredns_conf).encode('utf8'))
            f.close()
            call(['kubectl', '--context', 'kind-kind', 'apply', '-n', 'kube-system', '-f', f.name])
