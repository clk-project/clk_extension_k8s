#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import grp
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from shlex import split

import click
from click_project.config import config
from click_project.decorators import (argument, flag, group, option,
                                      param_config)
from click_project.lib import (call, cd, check_output, deepcopy, download,
                               extract, get_keyring, is_port_available,
                               makedirs, move, read, rm, tempdir,
                               temporary_file, updated_env, which)
from click_project.log import get_logger

LOGGER = get_logger(__name__)


class KubeCtl:
    def __init__(self):
        self.context = None

    def call(self, arguments):
        call(['kubectl', '--context', self.context] + arguments)

    def output(self, arguments):
        return check_output(['kubectl', '--context', self.context] + arguments)


@group()
@param_config('kubectl', '--context', '-c', typ=KubeCtl, help="The kubectl context to use", default='k3d-k3s-default')
def k8s():
    """Manipulate k8s"""


bin_dir = Path('~/.local/bin').expanduser()
k3d_url = 'https://github.com/rancher/k3d/releases/download/v4.4.4/k3d-linux-amd64'
helm_url = 'https://get.helm.sh/helm-v3.6.0-linux-amd64.tar.gz'
kubectl_url = 'https://dl.k8s.io/release/v1.21.2/bin/linux/amd64/kubectl'
tilt_url = 'https://github.com/tilt-dev/tilt/releases/download/v0.22.3/tilt.0.22.3.linux.x86_64.tar.gz'
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
    if not force and not which("k3d"):
        force = True
        LOGGER.info("Could not find k3d")
    if which("k3d"):
        found_k3d_version = re.match('k3d version (.+)', check_output(['k3d', '--version'])).group(1)
    if not force and found_k3d_version != k3d_version:
        force = True
        LOGGER.info(f"Found an older version of k3d ({found_k3d_version}) than the requested one {k3d_version}")
    if force:
        download(k3d_url, outdir=bin_dir, outfilename='k3d', mode=0o755)
    else:
        LOGGER.info("No need to install k3d, force with --force")


@install_dependency.command()
@flag('--force', help="Overwrite the existing binaries")
def helm(force):
    """Install helm"""
    helm_version = re.search('helm-(v[0-9.]+)', helm_url).group(1)
    if not force and not which("helm"):
        force = True
        LOGGER.info("Could not find helm")
    if which("helm"):
        found_helm_version = re.search('Version:"(v[0-9.]+)"', check_output(['helm', 'version'])).group(1)
    if not force and found_helm_version != helm_version:
        force = True
        LOGGER.info(f"Found an older version of helm ({found_helm_version}) than the requested one {helm_version}")
    if force:
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
    if not force and not which("tilt"):
        force = True
        LOGGER.info("Could not find tilt")
    if which("tilt"):
        found_tilt_version = re.match('(v[0-9.]+)', check_output(['tilt', 'version'])).group(1)
    if not force and found_tilt_version != tilt_version:
        force = True
        LOGGER.info(f"Found an older version of tilt ({found_tilt_version}) than the requested one {tilt_version}")
    if force:
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
    if not force and not which("kubectl"):
        force = True
        LOGGER.info("Could not find kubectl")
    if which("kubectl"):
        found_kubectl_version = re.match('Client Version: .+ GitVersion:"(v[0-9.]+)"',
                                         check_output(['kubectl', 'version', '--client=true'], failok=True)).group(1)
    if not force and found_kubectl_version != kubectl_version:
        force = True
        LOGGER.info(
            f"Found an older version of kubectl ({found_kubectl_version}) than the requested one {kubectl_version}")
    if force:
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
@flag('--recreate', help="Recreate it if it already exists")
def create_cluster(name, recreate):
    """Create a k3d cluster"""
    if name in [cluster['name'] for cluster in json.loads(check_output(split('k3d cluster list -o json')))]:
        if recreate:
            call(["k3d", "cluster", "delete", name])
        else:
            LOGGER.info(f"A cluster with the name {name} already exists. Nothing to do.")
            return

    if not is_port_available(80):
        raise click.ClickException("Port 80 is already in use by another process. Please stop this process and retry.")
    if not is_port_available(443):
        raise click.ClickException("Port 443 is already in use by another process. Please stop this process and retry.")

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
@option('--version', default='v1.2.0', help="The version of cert-manager chart to install")
def install_cert_manager(version):
    """Install a certificate manager in the current cluster"""
    call(['helm', 'repo', 'add', 'jetstack', 'https://charts.jetstack.io'])
    call([
        'helm', '--kube-context', config.kubectl.context,
        'upgrade', '--install', '--create-namespace', '--wait', 'cert-manager', 'jetstack/cert-manager',
        '--namespace', 'cert-manager',
        '--version', version,
        '--set', 'installCRDs=true',
        '--set', 'ingressShim.defaultIssuerName=local',
        '--set', 'ingressShim.defaultIssuerKind=ClusterIssuer',
    ])  # yapf: disable
    # generate a certificate authority for the cert-manager
    with tempdir() as d, cd(d):
        ca_key = check_output(['docker', 'run', '--rm', 'alpine/openssl', 'genrsa', '2048'])
        with open("ca.key", "w") as f:
            f.write(ca_key)

        ca_crt = check_output([
            'docker', 'run', '--rm', '--entrypoint', '/bin/sh', 'alpine/openssl', '-c',
            'echo -e "' + '\\n'.join(ca_key.split(sep='\n')) +
            '" | openssl req -x509 -new -nodes -key /dev/stdin -subj /CN=localhost -days 3650' +
            ' -reqexts v3_req -extensions v3_ca',
        ])  # yapf: disable
        with open("ca.crt", "w") as f:
            f.write(ca_crt)

        ca_secret = config.kubectl.output([
            'create', 'secret', 'tls', 'ca-key-pair',
            '--cert=ca.crt',
            '--key=ca.key',
            '--namespace=cert-manager',
            '--dry-run=client',
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
def install_dnsmasq():
    """Install a dnsmasq server resolving *.localhost to 127.0.0.1. Supported OS: macOS."""
    if sys.platform == "darwin":
        call(['brew', 'install', 'dnsmasq'])
        brew_prefix = check_output(['brew', '--prefix']).rstrip("\n")
        with open(brew_prefix + "/etc/dnsmasq.conf", "r+") as f:
            line_found = any("address=/localhost/127.0.0.1" in line for line in f)
            if not line_found:
                f.seek(0, os.SEEK_END)
                f.write("\naddress=/localhost/127.0.0.1\n")
        call(['sudo', 'brew', 'services', 'restart', 'dnsmasq'])
        call(['sudo', 'mkdir', '-p', '/etc/resolver'])
        with temporary_file() as f:
            f.write("nameserver 127.0.0.1\n".encode('utf8'))
            call(['sudo', 'cp', f.name, '/etc/resolver/localhost'])

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
    LOGGER.status('Everything worked well. Now enjoy your new cluster ready to go!')


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


@k8s.command()
@option('--force/--no-force', '-f', help="Force update")
@option('--touch', '-t', help="Touch this file or directory when update is complete")
@option('--experimental-oci/--no-experimental-oci', default=True, help="Activate experimental OCI feature")
@option('packages', '--package', '-p', multiple=True, help="Other helm dir to package and include in the dependencies")
@option('--remove/--no-remove', default=True, help="Remove extra dependency that may still be there")
@argument('path', default='.', required=False, help="Helm chart path")
def helm_dependency_update(path, force, touch, experimental_oci, packages, remove):
    """Update helm dependencies"""
    import yaml
    ctx = click.get_current_context()
    chart = yaml.load(open(f'{path}/Chart.yaml'), Loader=yaml.FullLoader)
    # generate the packages
    generated_packages = set()
    with tempdir() as d:
        # call the same command without --package for each package
        for package in packages:
            ctx.invoke(helm_dependency_update,
                       path=package,
                       force=force,
                       experimental_oci=experimental_oci,
                       remove=remove)
            pp = os.path.abspath(package)
            with cd(d):
                call(['helm', 'package', pp])
        # and move the generated packages to the chart dir
        generated_packages = set(os.listdir(d))
        for gp in generated_packages:
            if os.path.exists(f'{path}/charts/{gp}'):
                rm(f'{path}/charts/{gp}')
            move(f'{d}/{gp}', f'{path}/charts')
    # check wether we need to update the dependencies or not
    deps_to_update = []
    depArchives = set()
    for dep in chart.get('dependencies', []):
        name = f'{dep["name"]}-{dep["version"]}.tgz'
        matched_generated_packages = [gp for gp in generated_packages if name.startswith(gp[:-len('.tgz')])]
        if force and not matched_generated_packages:
            depArchives.add(name)
            deps_to_update.append(dep)
        if os.path.exists(f'{path}/charts/{name}'):
            depArchives.add(name)
        elif matched_generated_packages:
            LOGGER.warning(f"{name} loosely matched to package {matched_generated_packages[0]}")
            depArchives.add(matched_generated_packages[0])
        else:
            LOGGER.info(f"{name} is missing, updating")
            depArchives.add(name)
            deps_to_update.append(dep)
    if deps_to_update:
        # create a copy of Chart.yaml without the dependencies we don't want to redownload
        # in a temporary directory
        chart_to_update = deepcopy(chart)
        chart_to_update['dependencies'] = deps_to_update
        with tempdir() as d, open(f'{d}/Chart.yaml', 'w') as f:
            yaml.dump(chart_to_update, f)
            # download the dependencies
            if experimental_oci:
                with updated_env(HELM_EXPERIMENTAL_OCI='1'):
                    call(['helm', 'dependency', 'update', d])
            else:
                call(['helm', 'dependency', 'update', d])
            # and move them to the real charts directory
            generated_dependencies = set(os.listdir(f'{d}/charts'))
            for gd in generated_dependencies:
                makedirs(f'{path}/charts')
                if os.path.exists(f'{path}/charts/{gd}'):
                    rm(f'{path}/charts/{gd}')
                move(f'{d}/charts/{gd}', f'{path}/charts/{gd}')
    if (deps_to_update or packages) and touch:
        LOGGER.action(f"touching {touch}")
        os.utime(touch)
    if remove:
        for archive in os.listdir(f'{path}/charts'):
            if archive.endswith('.tgz') and archive not in depArchives:
                LOGGER.warning(f"Removing extra dependency: {archive}")
                rm(f'{path}/charts/{archive}')


@k8s.command()
@option('--docker-login/--no-docker-login', '-d', help="Also log into docker")
@option('--helm-login/--no-helm-login', '-h', help="Also log into helm")
@option('--export-password', '-p', help="Export the passwords that directory, with the registry host as name")
@argument('secret', help="K8s secret to use")
def docker_credentials(docker_login, helm_login, secret, export_password):
    """Extract the docker credentials from a k8s secret"""
    creds = config.kubectl.output(
        ['get', 'secret', secret, '--template', '{{index .data ".dockerconfigjson" | base64decode }}'])
    creds = json.loads(creds)
    for registry, values in creds['auths'].items():
        if docker_login:
            check_output(['docker', 'login', registry, '-u', values['username'], '-p', values['password']])
        if helm_login:
            with updated_env(HELM_EXPERIMENTAL_OCI='1'):
                check_output(
                    ['helm', 'registry', 'login', registry, '-u', values['username'], '-p', values['password']])
    if export_password:
        makedirs(export_password)
        for registry, values in creds['auths'].items():
            f_path = f'{export_password}/{registry}'
            if not os.path.exists(f_path) or read(f_path) != values['password']:
                with open(f_path, 'w') as f:
                    LOGGER.action(f'writing to {f_path}')
                    f.write(values['password'])
    print(json.dumps(creds['auths']))
