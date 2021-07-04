#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import os
import subprocess
import grp
import json
import re
import sys
import time
from pathlib import Path
from shlex import split

import click

from click_project.decorators import (
    argument,
    group,
    option,
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
    get_keyring,
)
from click_project.log import get_logger
from click_project.config import config

LOGGER = get_logger(__name__)


class KubeCtl:
    def __init__(self):
        self.context = None

    def call(self, arguments):
        call(['kubectl', '--context', self.context] + arguments)

    def output(self, arguments):
        return check_output(['kubectl', '--context', self.context] + arguments)


@group()
@param_config('kubectl', '--context', typ=KubeCtl, help="The kubectl context to use", default='k3d-k3s-default')
def k8s():
    """Manipulate k8s"""


bin_dir = Path('~/.local/bin').expanduser()
k3d_url = 'https://github.com/rancher/k3d/releases/download/v4.4.4/k3d-linux-amd64'
helm_url = 'https://get.helm.sh/helm-v3.6.0-linux-amd64.tar.gz'
kubectl_url = 'https://dl.k8s.io/release/v1.21.1/bin/linux/amd64/kubectl'
tilt_url = 'https://github.com/tilt-dev/tilt/releases/download/v0.21.0/tilt.0.21.0.linux.x86_64.tar.gz'
k3d_dir = os.path.expanduser('~/.k3d')

cluster_issuer = '''apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: local
spec:
  ca:
    secretName: ca-key-pair
'''


@k8s.command()
def doctor():
    """Check if you have everything needed to run the stack."""
    docker = which('docker')
    if docker is None:
        raise click.UsageError("You need to install docker")
    if sys.platform == 'linux':
        if 'docker' not in [grp.getgrgid(g).gr_name for g in os.getgroups()]:
            raise click.UsageError("You need to add the current user in the docker group")
    LOGGER.info("We did not find a reason to believe you will have trouble playing with the stack")


@k8s.group(default_command='all')
def install_dependency():
    """Install the dependencies needed to setup the stack"""
    # call(['sudo', 'apt', 'install', 'libnss-myhostname', 'docker.io'])


@install_dependency.command()
@flag('--force', help="Overwrite the existing binaries")
def k3d(force):
    """Install k3d"""
    k3d_version = re.search('/(v[0-9.]+)/', k3d_url).group(1)
    if force or not which('k3d') \
            or re.match('k3d version (.+)', check_output(['k3d', '--version'])).group(1) != k3d_version:
        download(k3d_url, outdir=bin_dir, outfilename='k3d', mode=0o755)
    else:
        LOGGER.info("No need to install k3d, force with --force")


@install_dependency.command()
@flag('--force', help="Overwrite the existing binaries")
def helm(force):
    """Install helm"""
    helm_version = re.search('helm-(v[0-9.]+)', helm_url).group(1)
    if force or not which('helm') \
            or re.search('Version:"(v[0-9.]+)"', check_output(['helm', 'version'])).group(1) != helm_version:
        with tempdir() as d:
            extract(helm_url, d)
            move(Path(d) / 'linux-amd64' / 'helm', bin_dir / 'helm')
            (bin_dir / 'helm').chmod(0o755)
    else:
        LOGGER.info("No need to install helm, force with --force")


@install_dependency.command()
@flag('--force', help="Overwrite the existing binaries")
def tilt(force):
    """Install tilt"""
    tilt_version = re.search('/(v[0-9.]+)/', tilt_url).group(1)
    if force or not which('tilt') \
            or re.match('(v[0-9.]+)', check_output(['tilt', 'version'])).group(1) != tilt_version:
        with tempdir() as d:
            extract(tilt_url, d)
            move(Path(d) / 'tilt', bin_dir / 'tilt')
    else:
        LOGGER.info('No need to install tilt, force with --force')


@install_dependency.command()
@flag('--force', help="Overwrite the existing binaries")
def kubectl(force):
    """Install kubectl"""
    kubectl_version = re.search('/(v[0-9.]+)/', kubectl_url).group(1)
    if force or not which('kubectl') \
            or re.match('Client Version: .+ GitVersion:"(v[0-9.]+)"',
                        check_output(['kubectl', 'version'])).group(1) != kubectl_version:
        download(kubectl_url, outdir=bin_dir, outfilename='kubectl', mode=0o755)
    else:
        LOGGER.info("No need to install kubectl, force with --force")


@install_dependency.command()
@flag('--force', help="Overwrite the existing binaries")
def _all(force):
    """Install all the dependencies"""
    ctx = click.get_current_context()
    ctx.invoke(kubectl, force=force)
    ctx.invoke(helm, force=force)
    ctx.invoke(tilt, force=force)
    ctx.invoke(k3d, force=force)


@k8s.command(flowdepends=['k8s.create-cluster'])
@option('--registry-provider', type=click.Choice(['gitlab']), help="What registry provider to connect to")
@option('--username', help="The username of the provider registry")
@option('--password', help="The password of the provider registry")
def install_docker_registry_secret(registry_provider, username, password):
    """Install the credential to get access to the given registry provider."""
    registries = {
        'gitlab': {
            'secret-name': 'gitlab-registry',
            'server': 'registry.gitlab.com',
        }
    }
    if registry_provider:
        if not (username and password):
            if res := get_keyring().get_password('click-project', f'{registry_provider}-registry-auth'):
                username, password = json.loads(res)
        username = username or click.prompt('username', hide_input=True, default='', show_default=False)
        password = password or click.prompt('password', hide_input=True, default='', show_default=False)
        registry = registries[registry_provider]
        config.kubectl.call([
            'create', 'secret', 'docker-registry', registry['secret-name'],
            f'--docker-server={registry["server"]}',
            f'--docker-username={username}',
            f'--docker-password={password}',
        ])  # yapf: disable
    else:
        LOGGER.status("No registry provider given, doing nothing.")


@k8s.command(flowdepends=['k8s.install-dependency.all'])
@flag('--reinstall', help="Reinstall it if it already exists")
def install_local_registry(reinstall):
    """Install the local registry"""
    if 'k3d-registry.localhost' in [
            registry['name'] for registry in json.loads(check_output(split('k3d registry list -o json')))
    ]:
        if reinstall:
            ctx = click.get_current_context()
            ctx.invoke(remove, target='registry')
        else:
            LOGGER.info("A registry with the name k3d-registry.localhost already exists." " Nothing to do.")
            return
    call(['k3d', 'registry', 'create', 'registry.localhost', '-p', '5000'])


@k8s.command(flowdepends=['k8s.install-local-registry'])
@argument('name', default='k3s-default', help="The name of the cluster to create")
def create_cluster(name):
    """Create a k3d cluster"""
    import yaml

    call([
        'k3d', 'cluster', 'create', name,
        '--wait',
        '--port', '80:80@loadbalancer',
        '--port', '443:443@loadbalancer',
        '--registry-use', 'k3d-registry.localhost:5000',
        '--k3s-agent-arg', '--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%',
        '--k3s-agent-arg', '--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%',
    ])  # yapf: disable
    traefik_conf = ''
    time.sleep(10)
    while not traefik_conf:
        try:
            traefik_conf = config.kubectl.output(['get', 'cm', 'traefik', '-n', 'kube-system', '-o', 'yaml'])
        except subprocess.CalledProcessError:
            time.sleep(5)
    traefik_conf = yaml.load(traefik_conf, Loader=yaml.FullLoader)
    traefik_conf['data']['traefik.toml'] = ('insecureSkipVerify = true\n' + traefik_conf['data']['traefik.toml'])
    with temporary_file() as f:
        f.write(yaml.dump(traefik_conf).encode('utf8'))
        f.close()
        config.kubectl.call(['apply', '-n', 'kube-system', '-f', f.name])
    config.kubectl.call(['delete', 'pod', '-l', 'app=traefik', '-n', 'kube-system'])


@k8s.command(flowdepends=['k8s.create-cluster'])
def install_cert_manager():
    """Install a certificate manager in the current cluster"""
    call(['helm', 'repo', 'add', 'jetstack', 'https://charts.jetstack.io'])
    call([
        'helm', '--kube-context', 'k3d-k3s-default',
        'upgrade', '--install', '--create-namespace', '--wait', 'cert-manager', 'jetstack/cert-manager',
        '--namespace', 'cert-manager',
        '--version', 'v1.2.0',
        '--set', 'installCRDs=true',
        '--set', 'ingressShim.defaultIssuerName=local',
        '--set', 'ingressShim.defaultIssuerKind=ClusterIssuer',
    ])  # yapf: disable
    # generate a certificate authority for the cert-manager
    with tempdir() as d, cd(d):
        call(['openssl', 'genrsa', '-out', 'ca.key', '2048'])
        call([
            'openssl', 'req', '-x509', '-new', '-nodes',
            '-key', 'ca.key',
            '-subj', '/CN=localhost',
            '-days', '3650',
            '-reqexts', 'v3_req',
            '-extensions', 'v3_ca',
            '-out', 'ca.crt',
        ])  # yapf: disable
        ca_secret = config.kubectl.output([
            'create', 'secret', 'tls', 'ca-key-pair',
            '--cert=ca.crt',
            '--key=ca.key',
            '--namespace=cert-manager',
            '--dry-run=true',
            '-o', 'yaml',
        ])  # yapf: disable
    with temporary_file() as f:
        f.write(f'''{ca_secret}
---
{cluster_issuer}
'''.encode('utf8'))
        f.close()
        config.kubectl.call(['apply', '-n', 'cert-manager', '-f', f.name])


@k8s.command(flowdepends=['k8s.create-cluster'])
@argument('domain', help="The domain name to define")
@argument('ip', default='172.17.0.1', help="The IP address for this domain")
def add_domain(domain, ip):
    """Add a new domain entry in K8s dns"""
    import yaml

    coredns_conf = config.kubectl.output(['get', 'cm', 'coredns', '-n', 'kube-system', '-o', 'yaml'])
    coredns_conf = yaml.load(coredns_conf, Loader=yaml.FullLoader)
    data = f'{ip} {domain}'
    if data not in coredns_conf['data']['NodeHosts'].split('\n'):
        coredns_conf['data']['NodeHosts'] = data + '\n' + coredns_conf['data']['NodeHosts']
        with temporary_file() as f:
            f.write(yaml.dump(coredns_conf).encode('utf8'))
            f.close()
            config.kubectl.call(['apply', '-n', 'kube-system', '-f', f.name])


@k8s.flow_command(flowdepends=['k8s.install-cert-manager'])
def flow():
    """Run the full k8s setup flow"""


@k8s.command()
@argument('target', type=click.Choice(['cluster', 'registry', 'all']), default='all', help="What should removed")
def remove(target):
    """Remove the k8s cluster"""
    if target in ['all', 'cluster']:
        call(['k3d', 'cluster', 'delete'])
    if target in ['all', 'registry']:
        call(['k3d', 'registry', 'delete', 'k3d-registry.localhost'])


@k8s.command()
def ipython():
    import IPython

    dict_ = globals()
    dict_.update(locals())
    IPython.start_ipython(argv=[], user_ns=dict_)
