#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import grp
import json
import os
import re
import subprocess
import sys
import tarfile
import webbrowser
from collections import Counter, defaultdict
from pathlib import Path
from shlex import split

import click
import yaml
from clk.config import config
from clk.decorators import argument, flag, group, option, param_config, table_fields, table_format
from clk.lib import (TablePrinter, call, cd, check_output, copy, deepcopy, download, extract, get_keyring,
                     is_port_available, ln, makedirs, move, read, rm, safe_check_output, tempdir, temporary_file,
                     updated_env, which)
from clk.log import get_logger
from clk.types import Suggestion

LOGGER = get_logger(__name__)

warned = False


def guess_context_and_distribution(context, distribution):
    warning = None
    if context is None and distribution is None:
        LOGGER.debug('Got no hint about the context or the distribution. I will try to guess them'
                     ' from the current context.')
        distribution = 'kind'
        context = None
        if current_context := config.kubectl.current_context():
            LOGGER.debug("There is a current context! Let's see whether I can make use of it!")
            guessed_context, guessed_distribution = guess_context_and_distribution(current_context, None)
            if guessed_context is not None or guessed_distribution is not None:
                LOGGER.debug(f'Guessed context {guessed_context} and distribution {distribution}')
                distribution = guessed_distribution
                context = guessed_context
            else:
                LOGGER.debug('Guessed nothing out of the current context....')
                warning = ('I could not infer a suitable distribution'
                           f' that would fit your current context ({current_context}).'
                           ' I will ignore it and use another one.'
                           ' See `clk k8s current-context` to know the'
                           ' inferred context ({context}) and `clk k8s current-context` to know the'
                           ' inferred distribution ({distribution}).'
                           ' Finally, use `clk k8s --distribution kind` to avoid this warning.')
        else:
            LOGGER.debug(f'No current context, falling back on distribution {distribution}'
                         ' and trying to infer a suitable context.')

    if context is None and distribution is not None:
        if distribution == 'k3d':
            context = 'k3d-k3s-default'
        if distribution == 'kind':
            context = 'kind-kind'
        LOGGER.debug(f'Given the distribution {distribution}, I inferred the context {context}')
    if context is not None and distribution is None:
        given_context = context
        if context.startswith('kind'):
            distribution = 'kind'
        elif context.startswith('k3d'):
            distribution = 'k3d'
        else:
            context = None
            distribution = None
        if context:
            LOGGER.debug(f'Given the context {given_context}, I inferred the distribution {distribution}')
        else:
            LOGGER.debug(f'Given the context {given_context}, I could not infer any distribution.'
                         ' Therefore I give up on that context.')
    global warned
    if warning and not warned:
        LOGGER.warning(warning.format(
            distribution=distribution,
            context=context,
        ), )
        warned = True
    return context, distribution


class K8s:

    def __init__(self):
        self._distribution = None
        self._explicit_distribution = None

    @property
    def distribution(self):
        result = guess_context_and_distribution(config.kubectl._explicit_context, self._explicit_distribution)[1]
        if result is None:
            raise click.UsageError('I could not infer a suitable distribution. Try providing one explicitly.')
        return result

    @distribution.setter
    def distribution(self, value):
        # this is called only when explicitly set by the user
        self._explicit_distribution = value


class KubeCtl:

    def __init__(self):
        self._explicit_context = None

    @property
    def context(self):
        result = guess_context_and_distribution(self._explicit_context, config.k8s._explicit_distribution)[0]
        if result is None:
            raise click.UsageError('I could not infer a suitable context. Try providing one explicitly.')
        return result

    @context.setter
    def context(self, value):
        # this is called only when explicitly set by the user
        self._explicit_context = value

    @staticmethod
    def list_contexts():
        return [
            line[1:].split()[0] for line in safe_check_output(['kubectl', 'config', 'get-contexts', '--no-headers'],
                                                              internal=True).splitlines()
        ]

    @staticmethod
    def current_context():
        return safe_check_output(['kubectl', 'config', 'current-context'], internal=True).strip()

    def call(self, arguments):
        context = self.context
        if context is not None:
            call(['kubectl', '--context', context] + arguments)
        else:
            call(['kubectl'] + arguments)

    def get(self, kind, name, namespace='default'):
        return [
            secret for secret in json.loads(
                config.kubectl.output(['get', kind, '--namespace', namespace, '--output', 'json']))['items']
            if secret['metadata']['name'] == name
        ]

    def output(self, arguments, **kwargs):
        context = self.context
        if context is not None:
            return check_output(['kubectl', '--context', context] + arguments, **kwargs)
        else:
            return check_output(['kubectl'] + arguments, **kwargs)


@group()
@param_config(
    'kubectl',
    '--context',
    '-c',
    typ=KubeCtl,
    help='The kubectl context to use',
    type=Suggestion(KubeCtl.list_contexts()),
)
@param_config(
    'k8s',
    '--distribution',
    '-d',
    typ=K8s,
    help='Distribution to use',
    type=click.Choice(['k3d', 'kind']),
)
def k8s():
    """Manipulate k8s"""


bin_dir = Path('~/.local/bin').expanduser()
urls = {
    'k3d': 'https://github.com/rancher/k3d/releases/download/v5.2.2/k3d-linux-amd64',
    'kind': 'https://kind.sigs.k8s.io/dl/v0.11.1/kind-linux-amd64',
    'helm': 'https://get.helm.sh/helm-v3.8.1-linux-amd64.tar.gz',
    'kubectl': 'https://dl.k8s.io/release/v1.21.2/bin/linux/amd64/kubectl',
    'kubectl_buildkit':
    'https://github.com/vmware-tanzu/buildkit-cli-for-kubectl/releases/download/v0.1.5/linux-v0.1.5.tgz',
    'tilt': 'https://github.com/tilt-dev/tilt/releases/download/v0.26.3/tilt.0.26.3.linux.x86_64.tar.gz',
    'earthly': 'https://github.com/earthly/earthly/releases/download/v0.6.12/earthly-linux-amd64',
}
kind_config = """
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: kind
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
        eviction-hard: "imagefs.available<1%,nodefs.available<1%"
        eviction-minimum-reclaim: "imagefs.available=1%,nodefs.available=1%"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
networking:
  disableDefaultCNI: true
"""

cluster_issuer = '''apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: local
spec:
  ca:
    secretName: ca-key-pair
'''


@k8s.command()
def current_distribution():
    """Print the currently used distribution

Useful to ensure we correctly guessed it."""
    print(config.k8s.distribution)


@k8s.command()
def current_context():
    """Print the currently used context

Useful to ensure we correctly guessed it."""
    print(config.kubectl.context)


@k8s.command()
def doctor():
    """Check if you have everything needed to run the stack."""
    warnings = 0
    docker = which('docker')
    if docker is None:
        raise click.UsageError('You need to install docker')
    if sys.platform == 'linux':
        if 'docker' not in [grp.getgrgid(g).gr_name for g in os.getgroups()]:
            raise click.UsageError('You need to add the current user in the docker group')
    if kube_context := config.kubectl.current_context():
        LOGGER.info(f'Trying to play with the kubernetes available with the context {kube_context}')
        LOGGER.info('I will check that kubectl build works correctly.'
                    ' It is a bit long and verbose. Please wait.')
        with tempdir() as d:
            (Path(d) / 'Dockerfile').write_text("""FROM alpine
RUN apk add busybox
""")
            try:
                call(['kubectl', 'build', d])
            except Exception:
                warnings += 1
                LOGGER.warning('I could not run kubectl build.'
                               " This is not a blocker but you won't be able to take advantage of fast builds.")
    else:
        LOGGER.warning('It looks like there is no kubernetes available so far.'
                       ' Run this command again after having started your stack so that I can make more tests.')
    if warnings:
        LOGGER.info(f"We found {warnings} reason{'s' if warnings else ''} for you to worry about the stack.")
    else:
        LOGGER.info('We did not find a reason to believe you will have trouble playing with the stack')


@k8s.group(default_command='all')
@flag('--force', help='Overwrite the existing binaries')
def install_dependency(force):
    """Install the dependencies needed to setup the stack"""
    # call(['sudo', 'apt', 'install', 'libnss-myhostname', 'docker.io'])
    config.k8s.install_dependencies_force = force


@install_dependency.command(handle_dry_run=True)
def kind():
    """Install kind"""
    if config.dry_run:
        LOGGER.info(f"(dry-run) download kind from {urls['kind']}")
        return
    force = config.k8s.install_dependencies_force
    if config.k8s.distribution != 'kind':
        LOGGER.status(f"I won't try to install kind because you use --distribution={config.k8s.distribution}."
                      ' To install kind, run clk k8s --distribution kind install-dependency kind.')
        return
    kind_version = re.search('/(v[0-9.]+)/', urls['kind']).group(1)
    if not force and not which('kind'):
        force = True
        LOGGER.info('Could not find kind')
    if which('kind'):
        found_kind_version = re.match('kind (v[0-9.]+) .+', check_output(['kind', 'version'])).group(1)
    if not force and found_kind_version != kind_version:
        force = True
        LOGGER.info(f'Found a different version of kind ({found_kind_version}) than the requested one {kind_version}')
    if force:
        download(urls['kind'], outdir=bin_dir, outfilename='kind', mode=0o755)
    else:
        LOGGER.status('No need to install kind, force with --force')


@install_dependency.command(handle_dry_run=True)
def k3d():
    """Install k3d"""
    if config.dry_run:
        LOGGER.info(f"(dry-run) download k3d from {urls['k3d']}")
        return
    force = config.k8s.install_dependencies_force
    if config.k8s.distribution != 'k3d':
        LOGGER.status(f"I won't try to install k3d because you use --distribution={config.k8s.distribution}."
                      ' To install k3d, run clk k8s --distribution k3d install-dependency k3d.')
        return
    k3d_version = re.search('/(v[0-9.]+)/', urls['k3d']).group(1)
    if not force and not which('k3d'):
        force = True
        LOGGER.info('Could not find k3d')
    if which('k3d'):
        found_k3d_version = re.match('k3d version (.+)', check_output(['k3d', '--version'])).group(1)
    if not force and found_k3d_version != k3d_version:
        force = True
        LOGGER.info(f'Found a different version of k3d ({found_k3d_version}) than the requested one {k3d_version}')
    if force:
        download(urls['k3d'], outdir=bin_dir, outfilename='k3d', mode=0o755)
    else:
        LOGGER.status('No need to install k3d, force with --force')


@install_dependency.command(handle_dry_run=True)
def helm():
    """Install helm"""
    if config.dry_run:
        LOGGER.info(f"(dry-run) download helm from {urls['helm']}")
        return
    force = config.k8s.install_dependencies_force
    helm_version = re.search('helm-(v[0-9.]+)', urls['helm']).group(1)
    if not force and not which('helm'):
        force = True
        LOGGER.info('Could not find helm')
    if which('helm'):
        found_helm_version = re.search('Version:"(v[0-9.]+)"', check_output(['helm', 'version'])).group(1)
    if not force and found_helm_version != helm_version:
        force = True
        LOGGER.info(f'Found a different version of helm ({found_helm_version}) than the requested one {helm_version}')
    if force:
        with tempdir() as d:
            extract(urls['helm'], d)
            move(Path(d) / 'linux-amd64' / 'helm', bin_dir / 'helm')
            (bin_dir / 'helm').chmod(0o755)
    else:
        LOGGER.status('No need to install helm, force with --force')


@install_dependency.command(handle_dry_run=True)
def tilt():
    """Install tilt"""
    if config.dry_run:
        LOGGER.info(f"(dry-run) download tilt from {urls['tilt']}")
        return
    force = config.k8s.install_dependencies_force
    tilt_version = re.search('/(v[0-9.]+)/', urls['tilt']).group(1)
    if not force and not which('tilt'):
        force = True
        LOGGER.info('Could not find tilt')
    if which('tilt'):
        found_tilt_version = re.match('(v[0-9.]+)', check_output(['tilt', 'version'])).group(1)
    if not force and found_tilt_version != tilt_version:
        force = True
        LOGGER.info(f'Found a different version of tilt ({found_tilt_version}) than the requested one {tilt_version}')
    if force:
        with tempdir() as d:
            extract(urls['tilt'], d)
            move(Path(d) / 'tilt', bin_dir / 'tilt')
    else:
        LOGGER.status('No need to install tilt, force with --force')


@install_dependency.command(handle_dry_run=True)
def earthly():
    """Install earthly"""
    if config.dry_run:
        LOGGER.info(f"(dry-run) download earthly from {urls['earthly']}")
        return
    force = config.k8s.install_dependencies_force
    earthly_version = re.search('/(v[0-9.]+)/', urls['earthly']).group(1)
    if not force and not which('earthly'):
        force = True
        LOGGER.info('Could not find earthly')
    if which('earthly'):
        found_earthly_version = re.match('^.*(v[0-9.]+).*$', check_output(['earthly', '--version'])).group(1)
    if not force and found_earthly_version != earthly_version:
        force = True
        LOGGER.info(
            f'Found a different version of earthly ({found_earthly_version}) than the requested one {earthly_version}')
    if force:
        download(urls['earthly'], bin_dir, 'earthly', mode=0o755)
    else:
        LOGGER.status('No need to install earthly, force with --force')


@install_dependency.command(handle_dry_run=True)
def kubectl():
    """Install kubectl"""
    if config.dry_run:
        LOGGER.info(f"(dry-run) download kubectl from {urls['kubectl']}")
        return
    force = config.k8s.install_dependencies_force
    kubectl_version = re.search('/(v[0-9.]+)/', urls['kubectl']).group(1)
    if not force and not which('kubectl'):
        force = True
        LOGGER.info('Could not find kubectl')
    if which('kubectl'):
        found_kubectl_version = re.match('Client Version: .+ GitVersion:"(v[0-9.]+)"',
                                         safe_check_output(['kubectl', 'version', '--client=true'])).group(1)
    if not force and found_kubectl_version != kubectl_version:
        force = True
        LOGGER.info(
            f'Found a different version of kubectl ({found_kubectl_version}) than the requested one {kubectl_version}')
    if force:
        download(urls['kubectl'], outdir=bin_dir, outfilename='kubectl', mode=0o755)
    else:
        LOGGER.status('No need to install kubectl, force with --force')


@install_dependency.command(handle_dry_run=True)
def kubectl_buildkit():
    """Install kubectl buildkit"""
    if config.dry_run:
        LOGGER.info(f"(dry-run) download kubectl_buildkit from {urls['kubectl_buildkit']}")
        return
    force = config.k8s.install_dependencies_force
    kubectl_buildkit_version = re.search('/(v[0-9.]+)/', urls['kubectl_buildkit']).group(1)
    found_kubectl_buildkit_version = False
    try:
        found_kubectl_buildkit_version = check_output(['kubectl', 'buildkit', 'version'], nostderr=True).splitlines()[0]
        found_kubectl_buildkit_version = re.sub(r'\n', '', found_kubectl_buildkit_version)
        if 'Client:' in found_kubectl_buildkit_version:
            found_kubectl_buildkit_version = found_kubectl_buildkit_version.replace('Client:', '').strip()
    except subprocess.CalledProcessError:
        found_kubectl_buildkit_version = False
        if location := which('kubectl-buildkit'):
            location = Path(location)
            if location.is_symlink():
                name = location.readlink().name
                if m := re.match('kubectl-buildkit-(.+)', name):
                    found_kubectl_buildkit_version = m.group(1)

    if not force and not found_kubectl_buildkit_version:
        force = True
        LOGGER.info('Could not find kubectl buildkit')
    if not force and found_kubectl_buildkit_version != kubectl_buildkit_version:
        force = True
        LOGGER.info(f'Found a different version of kubectl buildkit '
                    f'({found_kubectl_buildkit_version}) than the requested one {kubectl_buildkit_version}')
    if force:
        with tempdir() as d:
            extract(urls['kubectl_buildkit'], d)
            move(Path(d) / 'kubectl-build', bin_dir / 'kubectl-build')
            location = bin_dir / f'kubectl-buildkit-{kubectl_buildkit_version}'
            move(Path(d) / 'kubectl-buildkit', location)
            link_location = bin_dir / 'kubectl-buildkit'
            if link_location.exists():
                rm(link_location)
            ln(location, link_location)
    else:
        LOGGER.status('No need to install kubectl buildkit, force with --force')


@install_dependency.flow_command(
    flowdepends=[
        'k8s.install-dependency.kubectl',
        'k8s.install-dependency.kubectl-buildkit',
        'k8s.install-dependency.helm',
        'k8s.install-dependency.tilt',
        'k8s.install-dependency.earthly',
        'k8s.install-dependency.k3d',
        'k8s.install-dependency.kind',
    ],
    handle_dry_run=True,
)
def _all():
    """Install all the dependencies"""


@k8s.command(flowdepends=['k8s.create-cluster'])
@option('--registry-provider',
        type=click.Choice(['gitlab']),
        help='What registry provider to connect to',
        default='gitlab')
@option(
    '--username',
    help=('The username of the provider registry'
          ' (your gitlab id in case you use gitlab)'),
)
@option(
    '--password',
    help=('The password of the provider registry'
          ' (in case of gitlab, an API key with read_registry grants'
          ' generated using https://gitlab.com/-/profile/personal_access_tokens)'),
)
def install_docker_registry_credentials(registry_provider, username, password):
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
        LOGGER.status('No registry provider given, doing nothing.')


@k8s.command(flowdepends=['k8s.install-dependency.all'], handle_dry_run=True)
@flag('--reinstall', help='Reinstall it if it already exists')
def install_local_registry(reinstall):
    """Install k3d local registry"""
    if config.k8s.distribution == 'k3d':
        command = [
            'k3d',
            'registry',
            'create',
            'registry.localhost',
            '-p',
            '5000',
        ]
        if config.dry_run:
            LOGGER.info(f"(dry-run) create a registry using the command: {' '.join(command)}")
            return
        if 'k3d-registry.localhost' in [
                registry['name'] for registry in json.loads(check_output(split('k3d registry list -o json')))
        ]:
            if reinstall:
                ctx = click.get_current_context()
                ctx.invoke(remove, target='registry')
            else:
                LOGGER.status('A registry with the name k3d-registry.localhost already exists.'
                              ' Nothing to do.')
                return
        call(command)
    else:
        name = f'{config.k8s.distribution}-registry'
        command = f'docker run -d --restart=always -p 5000:5000 --name {name} registry:2'
        if config.dry_run:
            LOGGER.info(f'(dry-run) run: {command}')
            return
        exists = name in check_output(split('docker ps --format {{.Names}}')).split()
        if exists:
            LOGGER.status(f'A registry with the name {name} already exists.')
        else:
            call(split(command))


@k8s.command(
    flowdepends=['k8s.install-local-registry'],
    handle_dry_run=True,
)
@flag('--recreate', help='Recreate it if it already exists')
@option(
    '--volume',
    help=('Some local directory that will be made available in the cluster.'
          ' In docker style format host_path:container_path.'
          ' Only implemented for k3d for the time being.'),
)
def create_cluster(recreate, volume):
    """Create a k8s cluster"""
    if config.dry_run:
        LOGGER.info(f'(dry-run) create a {config.k8s.distribution} cluster.'
                    ' Here, there are many subtle hacks that'
                    ' are done before and after creating the cluster.'
                    ' Therefore I cannot describe it in dry-run mode.'
                    ' Please take a look at the code'
                    ' to find out what it does.')
        return
    if volume and config.k8s.distribution != 'k3d':
        LOGGER.warning('--local-volume is only implemented in k3d. It will be ignored.'
                       ' It can be easily implemented (https://stackoverflow.com/questions'
                       '/62694361/how-to-reference-a-local-volume-in-kind-kubernetes-in-docker)'
                       ' so please submit a pull request if you need it.')
    if config.k8s.distribution == 'k3d':
        name = 'k3s-default'
        clusters = json.loads(check_output(split('k3d cluster list -o json')))
        already_existing_clusters = [cluster for cluster in clusters if cluster['name'] == name]
        if already_existing_clusters:
            if recreate:
                call(['k3d', 'cluster', 'delete', name])
            else:
                LOGGER.status(f'A cluster with the name {name} already exists.')
                cluster = already_existing_clusters[0]
                if cluster['serversRunning'] == 0:
                    LOGGER.info('Starting k3d!')
                    call(['k3d', 'cluster', 'start', name])
                else:
                    LOGGER.status('Nothing to do!')
                return
    elif config.k8s.distribution == 'kind':
        name = 'kind'
        if name in check_output('kind get clusters'.split()).split('\n'):
            if recreate:
                call(['kind', 'delete', 'clusters', name])
            else:
                LOGGER.status(f'A cluster with the name {name} already exists. Nothing to do.')
                return
    else:
        raise click.ClickException('Unsupported distribution')

    if not is_port_available(80):
        raise click.ClickException('Port 80 is already in use by another process. Please stop this process and retry.')
    if not is_port_available(443):
        raise click.ClickException('Port 443 is already in use by another process. Please stop this process and retry.')

    if config.k8s.distribution == 'k3d':
        k3s_manifests = Path(__file__).parent.parent / 'k3s-manifests'
        cmd = [
            'k3d', 'cluster', 'create', name,
            '--wait',
            '--port', '80:80@loadbalancer',
            '--port', '443:443@loadbalancer',
            '--registry-use', 'k3d-registry.localhost:5000',
            '--k3s-arg', '--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%@agent:*',
            '--k3s-arg', '--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%@agent:*',
            '--k3s-arg', '--flannel-backend=none@server:*',
            '--k3s-arg', '--disable-network-policy@server:*',
            '--k3s-arg', '--no-deploy=traefik@server:*',
        ]  # yapf: disable
        for manifest in k3s_manifests.iterdir():
            cmd.extend(['--volume', f'{manifest}:/var/lib/rancher/k3s/server/manifests/{manifest.name}'])
        if volume:
            local_volume = volume.split(':')[0]
            makedirs(local_volume)
            cmd.extend(['--volume', volume])
        call(cmd)

    elif config.k8s.distribution == 'kind':
        reg_name = f'{config.k8s.distribution}-registry'
        kind_config_to_use = kind_config
        using_local_registry = reg_name in check_output(split('docker ps --format {{.Names}}')).split()
        if using_local_registry:
            kind_config_to_use += f"""
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:5000"]
    endpoint = ["http://{reg_name}:5000"]
"""
        with temporary_file(content=kind_config_to_use) as f:
            call(['kind', 'create', 'cluster', '--config', f.name])
        if using_local_registry:
            with temporary_file(content="""apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:5000"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
""") as f:
                call(['kubectl', 'apply', '-f', f.name])
            containers = check_output(
                ['docker', 'network', 'inspect', 'kind', '-f', '{{range .Containers}}{{.Name}} {{end}}']).split()
            if reg_name not in containers:
                call(split(f'docker network connect kind {reg_name}'))


@k8s.command(flowdepends=['k8s.install-ingress-controller'], handle_dry_run=True)
@option('--version', default='v1.2.0', help='The version of cert-manager chart to install')
def install_cert_manager(version):
    """Install a certificate manager in the current cluster"""
    namespace, name = 'cert-manager', 'cert-manager'
    if _helm_already_installed(namespace, name, version):
        LOGGER.status(f'{name} already installed in {namespace} with version {version}')
        return

    call([
        'helm', '--kube-context', config.kubectl.context,
        'upgrade', '--install', '--create-namespace', '--wait', name, name,
        '--namespace', namespace,
        '--version', version,
        '--repo', 'https://charts.jetstack.io',
        '--set', 'installCRDs=true',
        '--set', 'ingressShim.defaultIssuerName=local',
        '--set', 'ingressShim.defaultIssuerKind=ClusterIssuer',
    ])  # yapf: disable


@k8s.command(flowdepends=['k8s.install-cert-manager'], handle_dry_run=True)
def generate_certificate_authority():
    """Generate a certificate authority for cert-manager to use."""
    if config.dry_run:
        LOGGER.info('(dry-run) generating a certificate authority.'
                    ' I cannot describe in short what is done there.'
                    ' Please take a look at the code if you want to know more.')
        return
    secret_name = 'ca-key-pair'
    if config.kubectl.get('secret', secret_name, 'cert-manager'):
        LOGGER.debug(f'Already have a secret with name {secret_name}')
    else:
        with tempdir() as d, cd(d):
            ca_key = check_output(['docker', 'run', '--rm', 'alpine/openssl', 'genrsa', '2048'], nostderr=True)
            with open('ca.key', 'w') as f:
                f.write(ca_key)

            ca_crt = check_output([
                'docker', 'run', '--rm', '--entrypoint', '/bin/sh', 'alpine/openssl', '-c',
                'echo -e "' + '\\n'.join(ca_key.split(sep='\n')) +
                '" | openssl req -x509 -new -nodes -key /dev/stdin -subj /CN=localhost -days 3650' +
                ' -reqexts v3_req -extensions v3_ca',
            ])  # yapf: disable
            with open('ca.crt', 'w') as f:
                f.write(ca_crt)

            ca_secret = config.kubectl.output([
                'create', 'secret', 'tls', secret_name,
                '--cert=ca.crt',
                '--key=ca.key',
                '--namespace=cert-manager',
                '--dry-run=client',
                '-o', 'yaml',
            ])  # yapf: disable
    if config.kubectl.get('clusterissuer', 'local', 'cert-manager'):
        LOGGER.debug('Already have a cluster issuer with name local')
    else:
        with temporary_file() as f:
            f.write(f'''{ca_secret}
---
{cluster_issuer}
'''.encode('utf8'))
            f.close()
            config.kubectl.call(['apply', '-n', 'cert-manager', '-f', f.name])


def _helm_already_installed(namespace, name, version):
    releases = [
        release for release in json.loads(check_output(['helm', 'list', '--namespace', namespace, '--output', 'json']))
        if release['name'] == name
    ]
    if releases:
        release = releases[0]
        installed_version = release['chart'].split('-')[-1]
        if installed_version == version or 'v' + installed_version == version:
            return True
    return False


@k8s.command(flowdepends=['k8s.install-networkpolicies-controller'], handle_dry_run=True)
@option('--version', default='v3.35.0', help='The version of ingress-nginx chart to install')
def install_ingress_controller(version):
    """Install an ingress (ingress-nginx) in the current cluster"""
    namespace, name = 'ingress', 'ingress-nginx'
    if _helm_already_installed(namespace, name, version):
        LOGGER.status(f'{name} already installed in {namespace} with version {version}')
        return
    helm_extra_args = []
    if config.k8s.distribution == 'kind':
        helm_extra_args += [
            '--set', 'controller.service.type=NodePort',
            '--set', 'controller.hostPort.enabled=true',
        ]  # yapf: disable
    call([
        'helm', '--kube-context', config.kubectl.context,
        'upgrade', '--install', '--create-namespace', '--wait', name, name,
        '--namespace', namespace,
        '--repo', 'https://kubernetes.github.io/ingress-nginx',
        '--version', version,
        '--set', 'rbac.create=true',
        '--set', 'controller.extraArgs.enable-ssl-passthrough=',
    ] + helm_extra_args)  # yapf: disable


@k8s.command(handle_dry_run=True)
@option('--version', default='v18.0.2', help='The version of kube-prometheus-stack chart to install')
@option('--alertmanager/--no-alertmanager', help='Enable alertmanager')
@option('--pushgateway/--no-pushgateway', help='Enable pushgateway')
@option('--coredns/--no-coredns', help='Enable coreDns')
@option('--kubedns/--no-kubedns', help='Enable kubeDns')
@option('--kube-scheduler/--no-kube-scheduler', help='Enable kubeScheduler')
@option('--kube-controller-manager/--no-kube-controller-manager', help='Enable kubeControllerManager')
@option('--prometheus-retention', default='1d', help='Server retention')
@option('--prometheus-persistence-size', default='1Gi', help='Prometheus persistent volume size')
@option('--grafana-host', default='grafana.localhost', help='Grafana host')
@option('--grafana-persistence-size', default='1Gi', help='Grafana persistent volume size')
@option('--grafana-admin-password', default='grafana', help='Grafana admin password')
def install_kube_prometheus_stack(version, alertmanager, pushgateway, coredns, kubedns, kube_scheduler,
                                  kube_controller_manager, prometheus_retention, prometheus_persistence_size,
                                  grafana_host, grafana_persistence_size, grafana_admin_password):
    """Install a kube-prometheus-stack instance in the current cluster"""
    call([
        'helm', '--kube-context', config.kubectl.context,
        'upgrade', '--install', '--create-namespace', '--wait', 'kube-prometheus-stack',
        'kube-prometheus-stack',
        '--namespace', 'monitoring',
        '--version', version,
        '--repo', 'https://prometheus-community.github.io/helm-charts',
        '--set', 'alertmanager.enabled=' + str(alertmanager).lower(),
        '--set', 'pushgateway.enabled=' + str(pushgateway).lower(),
        '--set', 'coreDns.enabled=' + str(coredns).lower(),
        '--set', 'kubeDns.enabled=' + str(kubedns).lower(),
        '--set', 'kubeScheduler.enabled=' + str(kube_scheduler).lower(),
        '--set', 'kubeControllerManager.enabled=' + str(kube_controller_manager).lower(),
        '--set', 'prometheus.prometheusSpec.retention=' + prometheus_retention,
        '--set', 'prometheus.prometheusSpec.persistentVolume.size=' + prometheus_persistence_size,
        '--set', 'prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false',
        '--set', 'prometheus-node-exporter.hostRootFsMount=' +
                 str(not (config.k8s.distribution == 'docker-desktop')).lower(),
        '--set', 'grafana.ingress.enabled=true',
        '--set', 'grafana.ingress.hosts[0]=' + str(grafana_host),
        '--set', 'grafana.adminPassword=' + str(grafana_admin_password),
        '--set', 'grafana.persistence.enabled=true',
        '--set', 'grafana.persistence.size=' + grafana_persistence_size,
        '--set', 'grafana.deploymentStrategy.type=Recreate',
    ])  # yapf: disable


@k8s.command(flowdepends=['k8s.create-cluster'], handle_dry_run=True)
@option('--version', default='v0.50.0', help='The version of prometheus operator CRDs to install')
def install_prometheus_operator_crds(version):
    """Install prometheus operator CRDs in the current cluster"""
    base_url = ('https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/' +
                f'{version}/example/prometheus-operator-crd')
    for crd in [
            'monitoring.coreos.com_alertmanagerconfigs.yaml',
            'monitoring.coreos.com_alertmanagers.yaml',
            'monitoring.coreos.com_podmonitors.yaml',
            'monitoring.coreos.com_probes.yaml',
            'monitoring.coreos.com_prometheuses.yaml',
            'monitoring.coreos.com_prometheusrules.yaml',
            'monitoring.coreos.com_servicemonitors.yaml',
            'monitoring.coreos.com_thanosrulers.yaml',
    ]:
        config.kubectl.output(['apply', '-f', f'{base_url}/{crd}'])


@k8s.command(flowdepends=['k8s.create-cluster'], handle_dry_run=True)
@option('--version', default='v0.0.99', help='The version of reloader chart to install')
def install_reloader(version):
    """Install a reloader in the current cluster"""
    call([
        'helm', '--kube-context', config.kubectl.context,
        'upgrade', '--install', '--create-namespace', '--wait', 'reloader', 'reloader',
        '--repo', 'https://stakater.github.io/stakater-charts',
        '--namespace', 'reloader',
        '--version', version,
    ])  # yapf: disable


@k8s.command(flowdepends=['k8s.create-cluster'])
def install_dnsmasq():
    """Install a dnsmasq server resolving *.localhost to 127.0.0.1. Supported OS: macOS."""
    if sys.platform == 'darwin':
        call(['brew', 'install', 'dnsmasq'])
        brew_prefix = check_output(['brew', '--prefix']).rstrip('\n')
        with open(brew_prefix + '/etc/dnsmasq.conf', 'r+') as f:
            line_found = any('address=/localhost/127.0.0.1' in line for line in f)
            if not line_found:
                f.seek(0, os.SEEK_END)
                f.write('\naddress=/localhost/127.0.0.1\n')
        call(['sudo', 'brew', 'services', 'restart', 'dnsmasq'])
        call(['sudo', 'mkdir', '-p', '/etc/resolver'])
        with temporary_file(content='nameserver 127.0.0.1\n') as f:
            call(['sudo', 'cp', f.name, '/etc/resolver/localhost'])


@k8s.command(flowdepends=['k8s.create-cluster'])
@argument('domain', help='The domain name to define')
@argument('ip', default='172.17.0.1', help='The IP address for this domain')
@flag('--reset', help='Remove previous domains set by this command')
def add_domain(domain, ip, reset):
    """Add a new domain entry in K8s dns"""
    import yaml

    if config.k8s.distribution == 'k3d':
        coredns_conf = config.kubectl.output(['get', 'cm', 'coredns', '-n', 'kube-system', '-o', 'yaml'])
        coredns_conf = yaml.load(coredns_conf, Loader=yaml.FullLoader)
        data = f'{ip} {domain}'
        watermark = 'LINE ADDED BY CLK K8S'
        added_data = data + f' # {watermark}'
        dns_lines = coredns_conf['data']['NodeHosts'].split('\n')
        update = False
        if reset:
            dns_lines = [dns_line for dns_line in dns_lines if not re.match('.+' + watermark, dns_line)]
            update = True
        if (data not in dns_lines and added_data not in dns_lines):
            coredns_conf['data']['NodeHosts'] = added_data + '\n' + '\n'.join(dns_lines)
            update = True
        if update:
            with temporary_file() as f:
                f.write(yaml.dump(coredns_conf).encode('utf8'))
                f.close()
                config.kubectl.call(['apply', '-n', 'kube-system', '-f', f.name])
    if config.k8s.distribution == 'kind':
        if reset:
            LOGGER.warn('In, clk k8s add-domain, --reset only works with k3d for the time being')
        coredns_conf = config.kubectl.output(['get', 'cm', 'coredns', '-n', 'kube-system', '-o', 'yaml'])
        coredns_conf = yaml.load(coredns_conf, Loader=yaml.FullLoader)
        top_level_domain = domain.split('.')[-1]
        update = False
        watermark = 'LINE ADDED BY CLK K8S'
        if reset:
            new_value = '\n'.join(
                [line for line in coredns_conf['data']['Corefile'].splitlines() if not line.endswith(watermark)])
            if coredns_conf['data']['Corefile'] != new_value:
                coredns_conf['data']['Corefile'] = new_value
                update = True
        if f'hosts custom.hosts {top_level_domain}' not in coredns_conf['data']['Corefile']:
            data = '''
        hosts custom.hosts %s {
            fallthrough
        }
            '''
            data = data % top_level_domain
            last_bracket_index = coredns_conf['data']['Corefile'].rindex('}')
            coredns_conf['data']['Corefile'] = coredns_conf['data']['Corefile'][0:last_bracket_index] + data + '\n}\n'
            update = True
        data = f'{ip} {domain} # {watermark}'
        header, hosts, footer = re.match(
            r'^(.+hosts custom.hosts ' + top_level_domain + r' \{\n)([^}]*?\n?)(\s+fallthrough\s+\}.+)$',
            coredns_conf['data']['Corefile'], re.DOTALL).groups()
        if f'{data}\n' not in hosts:
            update = True
            coredns_conf['data']['Corefile'] = (header + hosts + '\n' + f'        {data}\n' + footer)

        if update:
            with temporary_file() as f:
                f.write(yaml.dump(coredns_conf).encode('utf8'))
                f.close()
                config.kubectl.call(['apply', '-n', 'kube-system', '-f', f.name])
                config.kubectl.call(['rollout', 'restart', '-n', 'kube-system', 'deployment/coredns'])


@k8s.flow_command(flowdepends=[
    'k8s.generate-certificate-authority',
    'k8s.install-prometheus-operator-crds',
    'k8s.install-reloader',
    'k8s.install-network-policy',
    'k8s.setup-credentials',
], handle_dry_run=True,)  # yapf: disable
def flow():
    """Run the full k8s setup flow"""
    if not config.dry_run:
        LOGGER.status('Everything worked well. Now enjoy your new cluster ready to go!')


@k8s.command()
@argument('target', type=click.Choice(['cluster', 'registry', 'all']), default='all', help='What should removed')
def remove(target):
    """Remove the k8s cluster"""
    if config.k8s.distribution == 'k3d':
        if target in ['all', 'cluster']:
            call(['k3d', 'cluster', 'delete'])
        if target in ['all', 'registry']:
            call(['k3d', 'registry', 'delete', 'k3d-registry.localhost'])
    elif config.k8s.distribution == 'kind':
        if target in ['all', 'cluster']:
            call(['kind', 'delete', 'cluster'])
        if target in ['all', 'registry']:
            reg_name = f'{config.k8s.distribution}-registry'
            if reg_name in check_output(split('docker ps --format {{.Names}}')).split():
                call(['docker', 'kill', reg_name])
                call(['docker', 'rm', reg_name])


@k8s.command()
def ipython():
    """Run a ipython interpreter

    Useful to help developing the module.

    """
    import IPython

    dict_ = globals()
    dict_.update(locals())
    IPython.start_ipython(argv=[], user_ns=dict_)


class ChartNotUpdatedYet(Exception):
    pass


class ChartDuplicatedDependencies(Exception):
    pass


class Chart:

    @staticmethod
    def compute_name(metadata):
        return f'{metadata["name"]}-{metadata["version"]}'

    def __init__(self, location):
        self.location = Path(location).resolve()
        self.subcharts_dir = self.location / 'charts'
        self.index_path = self.location / 'Chart.yaml'
        if not self.index_path.exists():
            raise click.UsageError(f'No file Chart.yaml in the directory {self.location}.'
                                   ' You must provide as argument the path to a'
                                   ' root helm chart directory (meaning with Chart.yaml inside)')
        self.index = yaml.load(self.index_path.open(), Loader=yaml.FullLoader)
        self.name = self.compute_name(self.index)
        self.dependencies = self.index.get('dependencies', [])
        self.sanity_check_dependencies()
        self.dependencies_fullnames = [self.compute_name(dep) for dep in self.dependencies]
        self._actual_dependencies = None

    def sanity_check_dependencies(self):
        deps = Counter([(dependency['name'], dependency['version'], dependency.get('alias'))
                        for dependency in self.dependencies])
        non_unique_deps = [f'{key[0]}-{key[1]} as {key[2]}' for key, value in deps.items() if value > 1]
        if non_unique_deps:
            raise ChartDuplicatedDependencies(f"{', '.join(non_unique_deps)} are non unique"
                                              f' in {self.location}')

    @property
    def actual_dependencies(self):
        if self._actual_dependencies is None:
            raise ChartNotUpdatedYet()
        return self._actual_dependencies

    def match_to_dependencies(self, name):
        """Check whether name is fulfilling a dependency of mine

        It can either be the exact name of a dependency, or a prefix of a
        dependency. This allows dependencies like some-dep.develop to be
        fulfilled by the name some-dep.
        """
        return [dependency for dependency in self.dependencies_fullnames if dependency.startswith(name)]

    def package(self, directory=None):
        """Package my content into the specified directory (or by default in the current working directory)"""
        directory = directory or os.getcwd()
        LOGGER.status(f'Packaging {self.name} (from {self.location}) in {directory}')
        with cd(directory):
            call(['helm', 'package', self.location])

    def get_dependencies_with_helm(self, deps_to_update):
        """Use helm to download the given dependencies"""
        # create a copy of Chart.yaml without the dependencies we don't want to redownload
        # in a temporary directory
        LOGGER.status(
            f"Starting to download {', '.join([self.compute_name(dep) for dep in deps_to_update])} for {self.name}")
        chart_to_update = deepcopy(self.index)
        chart_to_update['dependencies'] = deps_to_update
        with tempdir() as d, open(f'{d}/Chart.yaml', 'w') as f:
            yaml.dump(chart_to_update, f)
            # download the dependencies
            LOGGER.status("## The following is some helm logs, don't pay much attention to its gibberish")
            if config.experimental_oci:
                with updated_env(HELM_EXPERIMENTAL_OCI='1'):
                    call(['helm', 'dependency', 'update', d])
            else:
                call(['helm', 'dependency', 'update', d])
            LOGGER.status('## Done with strange helm logs')
            # and move them to the real charts directory
            generated_dependencies = set(os.listdir(f'{d}/charts'))
            for gd in generated_dependencies:
                makedirs(self.subcharts_dir)
                old_path = Path(d) / 'charts' / gd
                new_path = self.subcharts_dir / gd
                if new_path.exists():
                    rm(new_path)
                move(old_path, new_path)
        LOGGER.status(f"Downloaded {', '.join([self.compute_name(dep) for dep in deps_to_update])} for {self.name}")
        return generated_dependencies

    @staticmethod
    def find_one_source(dependency, subchart_sources):
        """If one subchart source is able to fulfill the dependency, return it."""
        match = [chart for chart in subchart_sources if dependency.startswith(chart.name)]
        if len(match) > 1:
            raise NotImplementedError()
        if not match:
            return None
        match = match[0]
        if dependency != match.name:
            LOGGER.warning(f'I guessed that the provided package {match.name} (available at {match.location})'
                           f' is a good candidate to fulfill the dependency {dependency}.'
                           ' Am I wrong?')
        return match

    def update_dependencies(self, subchart_sources, force=False):
        """Make sure the dependencies are up-to-date

        Using the subchart_sources to fulfill the dependencies when possible. It
        does not download dependencies that already are present, unless force is
        set to True.
        """
        to_fetch_with_helm = []
        to_resolve = set()
        updated = False
        if self.dependencies:
            makedirs(self.subcharts_dir)
        self._actual_dependencies = set()
        deps_to_seen_aliases = defaultdict(set)
        for dependency in self.dependencies:
            dependency_name = f'{self.compute_name(dependency)}.tgz'
            alias = dependency.get('alias')
            if alias in deps_to_seen_aliases[dependency_name]:
                raise NotImplementedError(
                    "I don't know how to handle"
                    ' two identical dependencies'
                    f'({dependency["name"]}-{dependency["alias"]}'
                    f' as {dependency.get("alias")})', )

            src = self.find_one_source(self.compute_name(dependency), subchart_sources)
            if src is not None:
                LOGGER.status(f'Using {src.name} (from {src.location}) to fulfill dependency {dependency_name}')
                src.update_dependencies(subchart_sources, force=force)
                src.package(self.subcharts_dir)
                updated = True
                actual_dependency = src.name
            elif force:
                LOGGER.status(f'I will unconditionally download {dependency_name} as a dependency of {self.name}'
                              ' (because of --force)')
                to_fetch_with_helm.append(dependency)
                actual_dependency = self.compute_name(dependency)
            elif (self.subcharts_dir / dependency_name).exists():
                LOGGER.status(f'{dependency_name} is already an up to date dependency of {self.name}')
                to_resolve.add(self.subcharts_dir / dependency_name)
                actual_dependency = self.compute_name(dependency)
            else:
                to_fetch_with_helm.append(dependency)
                actual_dependency = self.compute_name(dependency)
            self._actual_dependencies.add(actual_dependency)
        generated_dependencies = set()
        to_fetch_with_helm_unique = []
        to_fetch_with_helm_seen = set()
        for dependency in to_fetch_with_helm:
            identity = (dependency['name'], dependency['version'])
            if identity not in to_fetch_with_helm_seen:
                to_fetch_with_helm_unique.append(dependency)
                to_fetch_with_helm_seen.add(identity)
        if to_fetch_with_helm_unique:
            generated_dependencies = self.get_dependencies_with_helm(to_fetch_with_helm_unique)
        if generated_dependencies or to_resolve:
            with tempdir() as d:
                for dependency_to_resolve in generated_dependencies | to_resolve:
                    dependency_chart_location = self.subcharts_dir / dependency_to_resolve
                    temp_dependency_location = Path(d) / Path(dependency_to_resolve).name
                    with tarfile.open(dependency_chart_location, mode='r:gz') as tar:
                        tar.extractall(temp_dependency_location)
                    dependency_chart = Chart(next(temp_dependency_location.iterdir()))
                    updated_subcharts = dependency_chart.resolve_subcharts(subchart_sources=subchart_sources)
                    if updated_subcharts:
                        LOGGER.status(f'In {self.location}, substituting {dependency_chart.name} by the resolved one')
                        rm(dependency_chart_location)
                        dependency_chart.package(self.subcharts_dir)

            updated = True
        return updated

    def uncompress_dependencies(self):
        for dependency in self.subcharts_dir.iterdir():
            if dependency.name.endswith('tgz'):
                tarfile.open(name=str(dependency)).extractall(self.subcharts_dir)

    def resolve_subcharts(self, subchart_sources):
        updated = False
        if not self.subcharts_dir.exists():
            return updated
        for subchart_dir in self.subcharts_dir.iterdir():
            if subchart_dir.is_dir():
                subchart = Chart(subchart_dir)
                src = self.find_one_source(subchart.name, subchart_sources)
                if src is not None:
                    LOGGER.status(f'Substituting {subchart.location} by the source {src.name} from {src.location}')
                    rm(subchart.location)
                    copy(src.location, subchart.location)
                    updated = True
                else:
                    updated = subchart.resolve_subcharts(subchart_sources=subchart_sources) or updated
        return updated

    def clean_dependencies(self):
        """Remove any archive in the subcharts that is not fulfilling a
        dependency"""
        for file in self.subcharts_dir.iterdir():
            name = file.name[:-len('.tgz')]
            if name not in self.actual_dependencies:
                LOGGER.status(f'Removing {file}, not an actual dependency')
                rm(file)

    def __repr__(self):
        return f"<{self.__class__.__name__}('{self.location}')>"


@k8s.command()
@option('--force/--no-force', '-f', help='Force update')
@option('--touch', '-t', help='Touch this file or directory when update is complete')
@option('--experimental-oci/--no-experimental-oci', default=True, help='Activate experimental OCI feature')
@option('subchart_sources',
        '--package',
        '-p',
        multiple=True,
        type=Chart,
        help=('Directory of a helm package that can be used to override the dependency fetching mechanism'))
@option('--remove/--no-remove', default=True, help='Remove extra dependency that may still be there')
@flag('--uncompress', help=('Also leave out an uncompressed version.'
                            ' Ideal for grepping into them.'))
@argument('chart', default='.', type=Chart, required=False, help='Helm chart path')
def helm_dependency_update(chart, force, touch, experimental_oci, subchart_sources, remove, uncompress):
    """Update helm dependencies

    Like `helm dependency update` on steroids.

    It downloads the dependencies, like helm does, but allow you to provide some
    source of nested dependencies that will be packaged on the fly.

    If you provide other chart folders using --package, those that will match
    the dependencies will be packaged instead of downloading the dependency.

    This is done recursively, meaning that you can provide the sources of
    several dependencies and dependencies of dependencies and they will be
    appropriately packages and put one into the other.

    If you work on A, B and C with A depending on B depending on C. You want to
    easily package your project A with the sources of B and C automatically
    packaged into the package A.

    Also, if you work only on C, you'd want that packaging A would substitute on the fly C
    in the dependencies of B.

    That way, you simply have to run helm-dependency-update --package C A and
    you get A/charts/B.tgz that contains an updated C.

    """
    config.experimental_oci = experimental_oci
    updated_something = chart.update_dependencies(subchart_sources, force=force)
    if remove:
        chart.clean_dependencies()
    if uncompress:
        chart.uncompress_dependencies()
    if touch and updated_something:
        LOGGER.action(f'touching {touch}')
        os.utime(touch)


@k8s.command(ignore_unknown_options=True)
@argument('args', nargs=-1, help='Helm args')
def helm_template(args):
    """Run `helm template`, so that you can easily add parameters to it"""
    call(['helm', 'template'] + list(args))


@k8s.command(flowdepends=['k8s.create-cluster'])
def setup_credentials():
    """Placeholder command to setup the secrets

    This command does nothing but may be overridden by an alias or a customcommand
    to setup your secrets once the cluster is setup.

    In case you want to setup some secret after the cluster is created, this is
    as simple as running `clk command create bash k8s.setup-credentials` and
    write whatever behavior you want.

    You will likely want to make this new command have `k8s.create-cluster` in
    its flow, by adding the line `flowdepends: k8s.create-cluster` in its
    description for instance.

    You might want to take advantage of `clk k8s docker-credentials` and `clk
    k8s install-docker-registry-credentials` in this command.

    """
    LOGGER.debug('No credentials added in the cluster.'
                 ' You might want to customize this to automatically'
                 ' setup your credentials. See `clk k8s setup-credentials --help`'
                 ' for more information.')


@k8s.command(flowdepends=['k8s.install-docker-registry-credentials'])
@option('--docker-login/--no-docker-login', '-d', help='Also log into docker')
@option('--helm-login/--no-helm-login', '-h', help='Also log into helm')
@option('--export-password', '-p', help='Export the passwords that directory, with the registry host as name')
@argument('secret', help='Name of the k8s secret to use')
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


@k8s.command()
@option('--max-parallelism', '-j', default=1, help='Maximum parallelism')
@argument('name', default='buildkit', required=False, help='Runner name')
def create_buildkit_runner(max_parallelism, name):
    """Create a buildkit runner"""
    conf = f'''debug = false
[worker.containerd]
  namespace = "k8s.io"
  max-parallelism = {max_parallelism}
'''
    with temporary_file(content=conf) as f:
        call(['kubectl', 'buildkit', '--context', config.kubectl.context, 'create', '--config', f.name, name])


_features = {
    'kind': {
        'kubectl_build': True,
        'local_registry': False,
    },
    'k3d': {
        'kubectl_build': False,
        'local_registry': True,
    },
}


@k8s.command(handle_dry_run=True)
@table_format(default='key_value')
@table_fields(choices=['variable', 'value'])
@option(
    '--set-key',
    help=('Make the command output the given key with the given value.'
          'This is useful when you want to force the system as believing a feature is available in the parameters'),
    type=(str, bool),
    multiple=True,
)
@argument('keys',
          type=click.Choice(list(_features['kind'].keys())),
          nargs=-1,
          help='Only display these key values. If no key is provided, all the key values are displayed')
def features(fields, format, keys, set_key):
    """Show supported features for the current distribution"""
    for set_key_item in set_key:
        key, value = set_key_item
        _features[config.k8s.distribution][key] = value
    if config.k8s.distribution == 'kind':
        reg_name = f'{config.k8s.distribution}-registry'
        _features[config.k8s.distribution]['local_registry'] = reg_name in check_output(
            split('docker ps --format {{.Names}}')).split()
    with TablePrinter(fields, format) as tp:
        fs = _features[config.k8s.distribution]
        keys = keys or sorted(fs.keys())
        for k in keys:
            tp.echo(k, fs[k])


@k8s.command(handle_dry_run=True)
@table_format(default='key_value')
@table_fields(choices=['dependency', 'url'])
def show_dependencies(fields, format):
    """Print our dependencies."""
    with TablePrinter(fields, format) as tp:
        for dependency, url in urls.items():
            tp.echo(dependency, url)


@k8s.command(flowdepends=['k8s.create-cluster'], handle_dry_run=True)
def install_networkpolicies_controller():
    """Install cilium

So that you will have an implementation of network policies that actually works.
"""
    if config.k8s.distribution == 'kind':
        call([
            'helm', '--kube-context', config.kubectl.context, 'upgrade', '--install', '--wait',
            'cilium', 'cilium', '--version', '1.9.10',
            '--repo', 'https://helm.cilium.io/',
            '--namespace', 'kube-system',
            '--set', 'nodeinit.enabled=true',
            '--set', 'kubeProxyReplacement=partial',
            '--set', 'hostServices.enabled=false',
            '--set', 'externalIPs.enabled=true',
            '--set', 'nodePort.enabled=true',
            '--set', 'hostPort.enabled=true',
            '--set', 'bpf.masquerade=false',
            '--set', 'image.pullPolicy=IfNotPresent',
            '--set', 'ipam.mode=kubernetes',
            '--set', 'operator.replicas=1',
        ])  # yapf: disable
    else:
        LOGGER.status('Nothing to be done in k3d to install a policy network controller.'
                      ' We already installed calico when creating the server.')


network_policy = """kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: deny-from-other-namespaces
  namespace: default
spec:
  podSelector: {}
  ingress:
    - from:
        - podSelector: {}
          namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
        - podSelector: {}
          namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: logging
"""

extra_network_policy = """
        - podSelector: {}
          namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress
        - podSelector: {}
          namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: default
"""


@k8s.command(flowdepends=['k8s.create-cluster'], handle_dry_run=True)
@option('--strict/--permissive', default=True, help='Whether the network policy is permissive or strict')
def install_network_policy(strict):
    """Isolate the default namespace from the rest"""
    if config.dry_run:
        LOGGER.info('(dry-run) run kubectl apply to install some network policies. '
                    ' Take a look at the code to understand what is installed exactly.')
        return
    name = 'deny-from-other-namespaces'
    if config.kubectl.get('NetworkPolicy', name):
        LOGGER.debug(f'A network policy already exists with name {name}')
    else:
        content = network_policy
        if not strict:
            content += extra_network_policy
        with temporary_file(content=content) as f:
            config.kubectl.call(['apply', '-f', f.name])


@k8s.command(flowdepends=['k8s.flow'], ignore_unknown_options=True)
@argument('tilt-args', help='Arguments to give tilt', nargs=-1)
@flag('--open', help='Open the url in a browser')
@flag('--use-context', help='Try to use the appropriate context before running tilt')
def _tilt(tilt_args, open, use_context):
    'Run whatever is needed to run tilt'
    if open:
        webbrowser.open('http://localhost:10350')
    if use_context:
        context = {
            'k3d': 'k3d-k3s-default',
            'kind': 'kind-kind',
        }[config.k8s.distribution]
        call(['kubectl', 'config', 'use-context', context])
    call(['tilt', 'up'] + list(tilt_args))
