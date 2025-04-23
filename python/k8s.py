#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import grp
import gzip
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from shlex import split
from subprocess import Popen

import click
import tomli
import tomli_w
import yaml
from clk.config import config
from clk.core import cache_disk, run
from clk.decorators import argument, flag, group, option, table_fields, table_format
from clk.lib import (TablePrinter, call, cd, check_output, copy, createfile, deepcopy, download, extract, get_keyring,
                     glob, is_port_available, makedirs, move, quote, read, rm, safe_check_output, tempdir,
                     temporary_file, updated_env, which)
from clk.log import get_logger
from clk.types import DynamicChoice, Suggestion

LOGGER = get_logger(__name__)

warned = False

CLUSTER_NAME = 'clk-k8s'

EARTHLY_VERSION = '0.8.15'
HELM_VERSION = '3.15.2'
KUBECTL_VERSION = '1.30.2'
TILT_VERSION = '0.33.17'
KIND_VERSION = '0.23.0'
INGRESS_NGINX_VERSION = '4.10.1'
CERT_MANAGER_VERSION = '1.15.1'
METRICS_VERSION = '3.12.2'
RELOADER = '1.0.115'

bin_dir = Path('~/.local/bin').expanduser()
if not bin_dir.exists():
    os.makedirs(bin_dir)
platforms = {
    'linux': {
        'x86_64': {
            'kind':
            f'https://kind.sigs.k8s.io/dl/v{KIND_VERSION}/kind-linux-amd64',
            'helm':
            f'https://get.helm.sh/helm-v{HELM_VERSION}-linux-amd64.tar.gz',
            'kubectl':
            f'https://dl.k8s.io/release/v{KUBECTL_VERSION}/bin/linux/amd64/kubectl',
            'tilt': ('https://github.com/tilt-dev/tilt/releases/download/'
                     f'v{TILT_VERSION}/tilt.{TILT_VERSION}.linux.x86_64.tar.gz'),
            'earthly':
            f'https://github.com/earthly/earthly/releases/download/v{EARTHLY_VERSION}/earthly-linux-amd64',
        },
        'aarch64': {
            'kind':
            f'https://kind.sigs.k8s.io/dl/v{KIND_VERSION}/kind-linux-arm64',
            'helm':
            f'https://get.helm.sh/helm-v{HELM_VERSION}-linux-arm64.tar.gz',
            'kubectl':
            f'https://dl.k8s.io/release/v{KUBECTL_VERSION}/bin/linux/arm64/kubectl',
            'tilt': ('https://github.com/tilt-dev/tilt/releases/download/'
                     f'v{TILT_VERSION}/tilt.{TILT_VERSION}.linux.arm64.tar.gz'),
            'earthly':
            f'https://github.com/earthly/earthly/releases/download/v{EARTHLY_VERSION}/earthly-linux-arm64',
        },
    },
    'darwin': {
        'x86_64': {
            'kind':
            f'https://kind.sigs.k8s.io/dl/v{KIND_VERSION}/kind-darwin-amd64',
            'helm':
            f'https://get.helm.sh/helm-v{HELM_VERSION}-darwin-amd64.tar.gz',
            'kubectl':
            f'https://dl.k8s.io/release/v{KUBECTL_VERSION}/bin/darwin/amd64/kubectl',
            'tilt': ('https://github.com/tilt-dev/tilt/releases/download/'
                     f'v{TILT_VERSION}/tilt.{TILT_VERSION}.mac.x86_64.tar.gz'),
            'earthly':
            f'https://github.com/earthly/earthly/releases/download/v{EARTHLY_VERSION}/earthly-darwin-amd64',
        },
        'arm64': {
            'kind':
            f'https://kind.sigs.k8s.io/dl/v{KIND_VERSION}/kind-darwin-arm64',
            'helm':
            f'https://get.helm.sh/helm-v{HELM_VERSION}-darwin-arm64.tar.gz',
            'kubectl':
            f'https://dl.k8s.io/release/v{KUBECTL_VERSION}/bin/darwin/arm64/kubectl',
            'tilt': ('https://github.com/tilt-dev/tilt/releases/download/'
                     f'v{TILT_VERSION}/tilt.{TILT_VERSION}.mac.arm64.tar.gz'),
            'earthly':
            f'https://github.com/earthly/earthly/releases/download/v{EARTHLY_VERSION}/earthly-darwin-arm64',
        },
    },
}
urls = platforms.get(platform.system().lower(), {}).get(platform.machine())
if urls is None:
    supported_systems = ', '.join([f"{system} ({', '.join(assoc.keys())})" for system, assoc in platforms.items()])
    LOGGER.warning(f"We don't support {platform.system().lower()} ({platform.machine()})"
                   f' only those platforms are supported: {supported_systems}')


class InstallDependency:
    dependency_installers = []
    program_path: Path = None

    @classmethod
    def install_commands(cls, group):
        for dependency_installer in cls.dependency_installers:
            dependency_installer.install_command(group)

    def precondition(self):
        return True

    def compute_needed_version(self):
        raise NotImplementedError()

    def compute_version(self):
        raise NotImplementedError()

    def install(self):
        raise NotImplementedError()

    def post_install_check(self):
        return

    def need_install(self):
        force = config.k8s.install_dependencies_force
        if not force and not self.program_path.exists():
            force = True
            LOGGER.info(f'{self.name} is not present on your machine')
        self.needed_version = self.compute_needed_version()
        self.found_version = self.compute_version()
        if self.program_path.exists() and self.found_version is None:
            LOGGER.warning(f'I could not find the version of {self.name}')
        if not force and self.found_version != self.needed_version:
            force = True
            LOGGER.info(f'Found a different version of {self.name} ({self.found_version})'
                        f' than the requested one {self.needed_version}')
        return force

    def __init__(self, handle_dry_run=True):
        self.handle_dry_run = handle_dry_run
        self.name = self.program_path.name
        InstallDependency.dependency_installers.append(self)

    def install_command(self, group):

        def wrapper(*args, **kwargs):
            if urls is None:
                LOGGER.error(
                    f"I don't know how to install {self.name} on {platform.system().lower()} ({platform.machine()})")
                return
            if config.dry_run:
                LOGGER.info(f'(dry-run) download {self.name} from {urls[self.name]}')
                return
            if not self.precondition():
                return

            if self.need_install():
                if urls.get(self.name):
                    LOGGER.info(f'Let me install {self.name} for you at the version {self.needed_version}')
                    self.install()
                    if self.need_install():
                        LOGGER.warning(
                            f'After installing {self.name}, there is still something wrong.'
                            f' Please let us know at https://github.com/clk-project/clk_extension_k8s/issues')
                    else:
                        LOGGER.info(f'{self.name} correctly installed and appears to work')
                else:
                    LOGGER.warning(f"I don't know how to install {self.name} on your computer."
                                   f' Please install the appropriate version ({self.needed_version}).')
                self.post_install_check()
            else:
                LOGGER.status(f'No need to install {self.name}, force with --force')

        group.command(
            handle_dry_run=self.handle_dry_run,
            name=self.name,
            help=self.__doc__,
        )(wrapper)


class Kind(InstallDependency):
    """Install kind"""

    program_path = bin_dir / 'kind'

    def precondition(self):
        if config.k8s.distribution != 'kind':
            LOGGER.status(f"I won't try to install kind because you use --distribution={config.k8s.distribution}."
                          ' To install kind, run clk k8s --distribution kind install-dependency kind.')
            return False
        return True

    def compute_needed_version(self):
        return re.search('/(v[0-9.]+)/', urls['kind']).group(1)

    def compute_version(self):
        if self.program_path.exists():
            return re.match(
                'kind (v[0-9.]+) .+',
                check_output([Kind.program_path, 'version']),
            ).group(1)

    def install(self):
        download(
            urls['kind'],
            outdir=self.program_path.parent,
            outfilename=self.program_path.name,
            mode=0o755,
        )

    def post_install_check(self):
        if self.found_version is not None and self.found_version.split('.')[1] in (
                '12',
                '13',
                '14',
        ):
            LOGGER.error(
                f'You are using version {self.found_version} of {self.program_path}.'
                f' clk k8s is known not to work with versions of {self.program_path} greater than {self.needed_version}'
            )


Kind(handle_dry_run=True)


class Helm(InstallDependency):
    """Install helm"""

    program_path = bin_dir / 'helm'

    def compute_needed_version(self):
        return re.search('helm-(v[0-9.]+)', urls['helm']).group(1)

    def compute_version(self):
        if self.program_path.exists():
            return re.search(
                'Version:"(v[0-9.]+)"',
                check_output([str(Helm.program_path), 'version']),
            ).group(1)

    def install(self):
        with tempdir() as d:
            extract(urls['helm'], d)
            makedirs(str(self.program_path.parent))
            move(glob(Path(d) / '*' / 'helm')[0], self.program_path)
            self.program_path.chmod(0o755)


Helm(handle_dry_run=True)


class Tilt(InstallDependency):
    """Install tilt"""

    program_path = bin_dir / 'tilt'

    def compute_needed_version(self):
        return re.search('/(v[0-9.]+)/', urls['tilt']).group(1)

    def compute_version(self):
        if self.program_path.exists():
            return re.match('(v[0-9.]+)', check_output([str(Tilt.program_path), 'version'])).group(1)

    def install(self):
        with tempdir() as d:
            extract(urls['tilt'], d)
            makedirs(str(self.program_path.parent))
            move(Path(d) / 'tilt', str(self.program_path))


Tilt(handle_dry_run=True)


class Earthly(InstallDependency):
    """Install earthly"""

    program_path = bin_dir / 'earthly'

    def compute_needed_version(self):
        return re.search('/(v[0-9.]+)/', urls['earthly']).group(1)

    def compute_version(self):
        if self.program_path.exists():
            return re.match(
                '^.*(v[0-9.]+).*$',
                check_output([str(Earthly.program_path), '--version']),
            ).group(1)

    def install(self):
        makedirs(str(self.program_path.parent))
        download(
            urls['earthly'],
            str(self.program_path.parent),
            self.program_path.name,
            mode=0o755,
        )


Earthly(handle_dry_run=True)


def make_earthly_accept_http_connection_from_our_local_registry():
    config_file = Path('~/.earthly/config.yml').expanduser()
    makedirs(config_file.parent)
    config_ = {'global': {'buildkit_additional_config': ''}}
    if os.path.exists(config_file):
        config_ = yaml.safe_load(config_file.read_text())
        if 'global' not in config_:
            config_['global'] = {'buildkit_additional_config': ''}
    additional_config = tomli.loads(config_['global']['buildkit_additional_config'])
    registry = additional_config.get('registry', {})
    myregistry = registry.get(f'{config.k8s.host_ip}:{config.k8s.registry_port}', {})
    if not myregistry.get('http'):
        myregistry['http'] = True
        registry[f'{config.k8s.host_ip}:{config.k8s.registry_port}'] = myregistry
        additional_config['registry'] = registry
        config_['global']['buildkit_additional_config'] = tomli_w.dumps(additional_config)
        yaml.add_representer(str, str_presenter)
        config_file.write_text(yaml.dump(config_))


def str_presenter(dumper, data):
    """configures yaml for dumping multiline strings
    Ref: https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data
    """
    if data.count('\n') > 0:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


class Kubectl(InstallDependency):
    """Install kubectl"""

    program_path = bin_dir / 'kubectl'

    def compute_needed_version(self):
        return re.search('/(v[0-9.]+)/', urls['kubectl']).group(1)

    def compute_version(self):
        if self.program_path.exists():
            version_string = safe_check_output([str(Kubectl.program_path), 'version', '--client=true'])
            if match := re.match('Client Version: (.+) GitVersion:"(v[0-9.]+)"', version_string):
                return match.group(1)
            elif match := re.match('Client Version: (v[0-9.]+)', version_string):
                return match.group(1)
            else:
                raise click.UsageError(f'Could not identifiy the version of kubectl: {version_string}')

    def install(self):
        if self.program_path.exists():
            rm(self.program_path)
        download(
            urls['kubectl'],
            outdir=self.program_path.parent,
            outfilename=self.program_path.name,
            mode=0o755,
        )


Kubectl(handle_dry_run=True)


class HelmApplication:

    def __init__(self, namespace, name, version):
        self.namespace = namespace
        self.name = name
        self.version = version

    def _already_installed(self):
        releases = [
            release for release in json.loads(
                check_output([
                    str(Helm.program_path),
                    '--kube-context',
                    config.kubectl.context,
                    'list',
                    '--namespace',
                    self.namespace,
                    '--output',
                    'json',
                ])) if release['name'] == self.name
        ]
        if releases:
            release = releases[0]
            installed_version = release['chart'].split('-')[-1]
            if (installed_version == self.version or 'v' + installed_version == self.version):
                if release['status'] != 'deployed':
                    LOGGER.warning(f'{self.name} was already installed, but it had the status {release["status"]}.')
                    LOGGER.warning(
                        'This may happen when helm reached a timeout but the application was correctly installed.')
                    LOGGER.warning("Let's try to install it again and see what happens.")
                    return False
                return True
        return False

    def install(self, force, helm_args):
        if not force and self._already_installed():
            LOGGER.status(f'{self.name} already installed in'
                          f' namespace {self.namespace}'
                          f' with version {self.version}')
            return
        try:
            self._helm_install([
                self.name,
                self.name,
                '--namespace',
                self.namespace,
                '--version',
                self.version,
            ] + helm_args)
        except SilentCallFailed as e:
            LOGGER.error(f'The installation with helm of {self.name} failed')
            if ('content deadline exceeded' in e.content.strip().splitlines()[-1]
                    or 'timed out waiting' in e.content.strip().splitlines()[-1]):
                LOGGER.warning('It looks like it was due to a time out,'
                               ' so may be you can try running the command'
                               ' again and everything may be alright.')
                exit(5)

    @staticmethod
    def _helm_install(args):
        common_args = [
            str(Helm.program_path),
            '--kube-context',
            config.kubectl.context,
            'upgrade',
            '--install',
            '--create-namespace',
            '--wait',
        ]
        if config.develop:
            common_args.append('--debug')

        _silent_call(common_args + args)


def get_resource_name(item):
    try:
        return item['metadata']['name']
    except KeyError:
        return item['metadata']['labels']['kubernetes.io/metadata.name']


def guess_context_and_distribution(context, distribution):
    warning = None
    if context is None and distribution is None:
        LOGGER.debug('Got no hint about the context or the distribution. I will try to guess them'
                     ' from the current context.')
        distribution = 'kind'
        context = None
        if current_context := config.kubectl.current_context():
            LOGGER.debug("There is a current context! Let's see whether I can make use of it!")
            (
                guessed_context,
                guessed_distribution,
            ) = guess_context_and_distribution(current_context, None)
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
                           ' inferred context ({context}) and `clk k8s current-distribution` to know the'
                           ' inferred distribution ({distribution}).'
                           ' Finally, use `clk k8s --distribution kind` to avoid this warning.')
        else:
            LOGGER.debug(f'No current context, falling back on distribution {distribution}'
                         ' and trying to infer a suitable context.')

    if context is None and distribution is not None:
        if distribution == 'kind':
            context = f'kind-{CLUSTER_NAME}'
        LOGGER.debug(f'Given the distribution {distribution}, I inferred the context {context}')
    if context is not None and distribution is None:
        given_context = context
        if context.startswith('kind'):
            distribution = 'kind'
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
        self._host_ip = None

    @property
    def host_ip(self):
        if self._host_ip is None:
            self._host_ip = json.loads(check_output([
                'docker',
                'inspect',
                'bridge',
            ]))[0]['IPAM']['Config'][0]['Gateway']
        return self._host_ip

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
            line[1:].split()[0] for line in safe_check_output(
                [
                    str(Kubectl.program_path),
                    'config',
                    'get-contexts',
                    '--no-headers',
                ],
                internal=True,
            ).splitlines()
        ]

    @staticmethod
    def current_context():
        return safe_check_output(
            [str(Kubectl.program_path), 'config', 'current-context'],
            internal=True,
        ).strip()

    def call(self, arguments, silent=True):
        context = self.context
        caller = silent_call if silent is True else call
        if context is not None:
            caller([str(Kubectl.program_path), '--context', context] + arguments)
        else:
            caller([str(Kubectl.program_path)] + arguments)

    def get(self, kind, name=None, namespace='default', internal=False):
        LOGGER.action(f'Getting {kind}:{name}')
        if not internal and config.dry_run:
            return {}
        return [
            elem for elem in json.loads(
                config.kubectl.output(['get', kind, '--namespace', namespace, '--output', 'json']))['items']
            if not name or elem['metadata']['name'] == name
        ]

    def delete(self, kind, name, namespace='default', internal=False):
        LOGGER.action(f'Deleting {kind}:{name}')
        if not internal and config.dry_run:
            return None
        return self.call(['delete', kind, name, '--namespace', namespace])

    def output(self, arguments, **kwargs):
        context = self.context
        if context is not None:
            return check_output(
                [str(Kubectl.program_path), '--context', context] + arguments,
                **kwargs,
            )
        else:
            return check_output([str(Kubectl.program_path)] + arguments, **kwargs)

    def json(self, arguments, **kwargs):
        return json.loads(self.output(arguments + ['--output=json'], **kwargs))


@group()
@option(
    '--context',
    '-c',
    expose_class=KubeCtl,
    help='The kubectl context to use',
    type=Suggestion(KubeCtl.list_contexts()),
)
@option(
    '--distribution',
    '-d',
    expose_class=K8s,
    help='Distribution to use',
    type=click.Choice(['kind']),
)
@option(
    '--registry-port',
    help='Specify another port for the registry to listen to',
    expose_class=K8s,
    default=5000,
    type=int,
)
def k8s():
    """Manipulate k8s"""
    config.override_env['K8S_CONTEXT'] = config.kubectl.context
    config.init()


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
  extraMounts:
    - hostPath: /tmp/kind
      containerPath: /tmp
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
                call([str(Kubectl.program_path), 'build', d])
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


InstallDependency.install_commands(install_dependency)


@install_dependency.flow_command(
    flowdepends=[
        'k8s.install-dependency.kubectl',
        'k8s.install-dependency.helm',
        'k8s.install-dependency.tilt',
        'k8s.install-dependency.earthly',
        'k8s.install-dependency.kind',
    ],
    handle_dry_run=True,
)
def _all():
    """Install all the dependencies"""


docker_registries_configs = {
    'dockerhub': {
        'secret-name': 'dockerhub-registry',
        'server': 'https://index.docker.io/v1/',
    },
    'github': {
        'secret-name': 'github-registry',
        'server': 'ghcr.io',
    },
    'gitlab': {
        'secret-name': 'gitlab-registry',
        'server': 'registry.gitlab.com',
    },
    'aws': {
        'secret-name': 'aws-registry',
    },
}


@k8s.command(flowdepends=['k8s.create-cluster'], handle_dry_run=True)
@argument(
    'registry-provider',
    type=click.Choice(docker_registries_configs.keys()),
    help='What registry provider to connect to',
    default=list(docker_registries_configs)[0],
)
@option(
    '--username',
    help=('The username of the provider registry'
          ' (your gitlab id in case you use gitlab, or AWS in case of aws)'),
)
@option(
    '--password',
    help=('The password of the provider registry'
          ' (in case of gitlab, an API key with read_registry grants'
          ' generated using https://gitlab.com/-/profile/personal_access_tokens)'),
)
@option(
    '--server',
    help='Should be needed only when using aws, where it cannot be inferred easily',
)
@flag('--force', help='Overwrite the existing secret, default for aws that has very short lived token')
@option(
    '--docker-login/--no-docker-login',
    default=True,
    help='Also log into docker',
)
@option('--helm-login/--no-helm-login', default=True, help='Also log into helm')
@option('--k8s-login/--no-k8s-login', default=True, help='Also log into helm')
def registry_login(
    registry_provider,
    username,
    password,
    force,
    docker_login,
    server,
    helm_login,
    k8s_login,
):
    """Install the credential to get access to the given registry provider."""
    force = force or registry_provider == 'aws'
    registry = docker_registries_configs[registry_provider]
    secret_name = registry['secret-name']
    if not username and registry_provider == 'aws':
        username = 'AWS'
    if not password and registry_provider == 'aws':
        password = check_output(['aws', 'ecr', 'get-login-password'])
    if not (username and password):
        if username or password:
            LOGGER.warning('I need to be given both username and password to use them.'
                           ' Falling back on trying using the keyring.')
        if res := get_keyring().get_password('clk', f'{registry_provider}-registry-auth-user'):
            username = res
        else:
            LOGGER.warning('Could not find the username from your password manager')
        if res := get_keyring().get_password('clk', f'{registry_provider}-registry-auth-password'):
            password = res
        else:
            LOGGER.warning('Could not find the password from your password manager')
    username = username or click.prompt('username', hide_input=True, default='', show_default=False)
    password = password or click.prompt('password', hide_input=True, default='', show_default=False)
    if not server and registry_provider == 'aws':
        server = check_output([
            'aws',
            'ecr',
            'describe-repositories',
            '--query',
            'repositories[0].repositoryUri',
            '--output',
            'text',
        ]).split('/')[0]
    if not server:
        server = registry['server']
    if k8s_login:
        run = True
        if config.kubectl.get('secret', secret_name):
            if force:
                config.kubectl.delete('secret', secret_name)
            else:
                LOGGER.status(
                    f'There is already a secret called {secret_name}, doing nothing (unless called with --force)')
                run = False
        if run:
            config.kubectl.call(
                [
                    'create',
                    'secret',
                    'docker-registry',
                    secret_name,
                    f'--docker-server={server}',
                    f'--docker-username={username}',
                    f'--docker-password={password}',
                ]
            )  # yapf: disable
    if docker_login:
        silent_call(['docker', 'login', server, '-u', username, '-p', password])
    if helm_login:
        silent_call([
            str(Helm.program_path),
            'registry',
            'login',
            server,
            '-u',
            username,
            '-p',
            password,
        ])


@k8s.command(flowdepends=['k8s.create-cluster'])
def wait_ready():
    'Wait that the kubernetes node is ready'

    tries = 0
    threshold = 10
    time_to_sleep = 5
    node_info = config.kubectl.get('node', internal=True)
    while not all(
            c['status'] == 'True' for node in node_info for c in node['status']['conditions'] if c['type'] == 'Ready'):
        tries += 1
        msg = f'Waited {tries * time_to_sleep}s for the node to be ready.'
        logger = LOGGER.status
        if tries > threshold:
            msg += (" It's been a long time now, something may be wrong."
                    " I'm still waiting for eternity")
            logger = LOGGER.warning
        status_msg = '\n'.join([
            node['metadata']['name'] + ': ' + ', '.join(
                f"{condition['reason']} ({condition['message']})"
                for condition in node['status']['conditions']
                # ondy the Ready condition must be True, the other ones
                # must be False in a well working cluster.
                if (condition['type'] == 'Ready' and condition['status'] == 'False') or condition['status'] == 'True')
            for node in config.kubectl.get('node')
        ])
        msg += f'\n{status_msg}'
        logger(msg)
        time.sleep(time_to_sleep)
        node_info = config.kubectl.get('node')
    if tries > threshold:
        LOGGER.warning('The cluster has finally begun correctly.'
                       ' You can ignore this warning and the previous ones.'
                       ' Beware that your computer might not be powerful enough'
                       ' for a nice k8s experience.')


@k8s.command(flowdepends=['k8s.install-dependency.all'], handle_dry_run=True)
@flag('--reinstall', help='Reinstall it if it already exists')
def install_local_registry(reinstall):
    """Install the local registry that will store the docker images pulled by the cluster"""
    name = f'{config.k8s.distribution}-registry'
    command = f'docker run -d --restart=always -p {config.k8s.registry_port}:5000 --name {name} registry:2'
    if config.dry_run:
        LOGGER.info(f'(dry-run) run: {command}')
        return
    if (name in check_output(split('docker ps --format {{.Names}}')).split()):
        LOGGER.status(f'A registry with the name {name} already exists.')
    else:
        if (name in check_output(split('docker ps --all --format {{.Names}}')).split()):
            silent_call(split(f'docker rm {name}'))
        silent_call(split(command))

    make_earthly_accept_http_connection_from_our_local_registry()


@k8s.command(
    flowdepends=['k8s.install-local-registry'],
    handle_dry_run=True,
)
@flag('--recreate', help='Recreate it if it already exists')
@option(
    '--api-server-address',
    default='127.0.0.1',
    help='Use this in case you want to control the cluster remotely',
)
@option('--nodes', '-n', default=1, type=int, help='Number of nodes in the cluster')
@option(
    '--calico-version',
    default='v3.28.0',
    help='The version of calico to install along kind',
)
@flag('--use-public-dns', help="Don't rely on the host dns fallback resolving (only implemented in kind)")
def create_cluster(recreate, nodes, api_server_address, calico_version, use_public_dns):
    """Create a k8s cluster

    The option `--use-public-dns` may be needed to circumvent issues when
    discussing with the host dns

    For instance, in a Mac, running colima, running earthly-buildkit, running
    docker, running kind, I found out that the name resolutions using 192.168.5.2
    did not work. I'm did not find why.

    But using 1.1.1.1 in that case helps workaround that issue.

    """
    if config.dry_run:
        LOGGER.info(f'(dry-run) create a {config.k8s.distribution} cluster.'
                    ' Here, there are many subtle hacks that'
                    ' are done before and after creating the cluster.'
                    ' Therefore I cannot describe it in dry-run mode.'
                    ' Please take a look at the code'
                    ' to find out what it does.')
        return
    if config.k8s.distribution == 'kind':
        name = CLUSTER_NAME
        if name in silent_check_output([Kind.program_path, 'get', 'clusters']).split('\n'):
            if recreate:
                silent_call([str(Kind.program_path), 'delete', 'clusters', name])
            else:
                LOGGER.status(f'A cluster with the name {name} already exists. Nothing to do.')
                return
    else:
        raise click.ClickException('Unsupported distribution')

    if not is_port_available(80):
        raise click.ClickException('Port 80 is already in use by another process. Please stop this process and retry.')
    if not is_port_available(443):
        raise click.ClickException('Port 443 is already in use by another process. Please stop this process and retry.')

    if config.k8s.distribution == 'kind':
        reg_name = f'{config.k8s.distribution}-registry'
        kind_config_to_use = kind_config
        kind_config_to_use += '- role: worker\n' * (nodes - 1)
        using_local_registry = (reg_name in check_output(split('docker ps --format {{.Names}}')).split())
        if using_local_registry:
            kind_config_to_use += f"""
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."{config.k8s.host_ip}:{config.k8s.registry_port}"]
    endpoint = ["http://{reg_name}:5000"]
"""
        kind_config_to_use += f"""
networking:
  apiServerAddress: {api_server_address}
  disableDefaultCNI: true
  ipFamily: ipv4
"""
        with temporary_file(content=kind_config_to_use) as f:
            cmd = [
                str(Kind.program_path),
                'create',
                'cluster',
                '--name',
                CLUSTER_NAME,
                '--config',
                f.name,
            ]
            if config.log_level in ('debug', 'develop'):
                cmd += ['--loglevel', '3']
            silent_call(cmd)
        if use_public_dns:
            call([
                'docker', 'exec', f'{CLUSTER_NAME}-control-plane', 'bash', '-c',
                '''echo 'nameserver 1.1.1.1' > /etc/resolv.conf'''
            ])
        if using_local_registry:
            with temporary_file(content=f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "{config.k8s.host_ip}:{config.k8s.registry_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
""") as f:
                silent_call([str(Kubectl.program_path), 'apply', '-f', f.name])
            containers = check_output([
                'docker',
                'network',
                'inspect',
                'kind',
                '-f',
                '{{range .Containers}}{{.Name}} {{end}}',
            ]).split()
            if reg_name not in containers:
                silent_call(split(f'docker network connect kind {reg_name}'))
        # install calico, see https://docs.tigera.io/calico/latest/getting-started/kubernetes/kind
        config.kubectl.call([
            'create',
            '-f',
            f'https://raw.githubusercontent.com/projectcalico/calico/{calico_version}/manifests/calico.yaml',
        ])


@k8s.group()
def cert_manager():
    'Commands to deal with cert-manager'


@cert_manager.command(flowdepends=['k8s.install-ingress-controller'], handle_dry_run=True)
@option(
    '--version',
    default=f'v{CERT_MANAGER_VERSION}',
    help='The version of cert-manager chart to install',
)
@flag(
    '--force/--no-force',
    help='Force the installation even if the required version is already installed',
)
def _install(version, force):
    """Install a certificate manager in the current cluster"""
    HelmApplication('cert-manager', 'cert-manager', version).install(
        force,
        [
            '--repo',
            'https://charts.jetstack.io',
            '--set',
            'installCRDs=true',
            '--set',
            'ingressShim.defaultIssuerName=local',
            '--set',
            'ingressShim.defaultIssuerKind=ClusterIssuer',
        ],
    )


@k8s.command(flowdepends=['k8s.wait-ready'], handle_dry_run=True)
@option(
    '--version',
    default=f'v{METRICS_VERSION}',
    help='The version of metrics chart to install',
)
@flag(
    '--force/--no-force',
    help='Force the installation even if the required version is already installed',
)
def install_metrics_server(version, force):
    """Install the metrics in the current cluster"""
    HelmApplication('metrics', 'metrics-server', version).install(
        force,
        [
            '--repo',
            'https://kubernetes-sigs.github.io/metrics-server/',
            # see
            # https://www.zeng.dev/post/2023-kubeadm-enable-kubelet-serving-certs/ ,
            '--set=args[0]=--kubelet-insecure-tls'
        ],
    )


@cert_manager.command(flowdepends=['k8s.cert-manager.install'], handle_dry_run=True)
@option('--ca-key-path', type=Path, help='The key to use instead of generating one dynamically')
@option('--ca-crt-path',
        type=Path,
        help='The certificate to use instead of generating one dynamically (only makes sense if --ca-key is provided)')
def generate_certificate_authority(ca_key_path, ca_crt_path):
    """Generate a certificate authority for cert-manager to use."""
    if ca_crt_path and not ca_key_path:
        raise click.UsageError('--ca-key-path must be used when --ca-crt-path is provided')
    if config.dry_run:
        LOGGER.info('(dry-run) generating a certificate authority.'
                    ' I cannot describe in short what is done there.'
                    ' Please take a look at the code if you want to know more.')
        return
    secret_name = 'ca-key-pair'
    if config.kubectl.get('secret', secret_name, 'cert-manager'):
        LOGGER.debug(f'Already have a secret with name {secret_name}')
    else:

        def install_certificate_pair(key_path, crt_path):
            config.kubectl.output(
                [
                    'create',
                    'secret',
                    'tls',
                    secret_name,
                    f'--cert={crt_path}',
                    f'--key={key_path}',
                    '--namespace=cert-manager',
                    '-o',
                    'yaml',
                ]
            )  # yapf: disable

        def generate_certificate(ca_key):
            return check_output(
                [
                    'docker',
                    'run',
                    '--rm',
                    '--entrypoint',
                    '/bin/sh',
                    'alpine/openssl',
                    '-c',
                    'echo -e "'
                    + '\\n'.join(ca_key.split(sep='\n'))
                    + '" | openssl req -x509 -new -nodes -key /dev/stdin -subj /CN=localhost -days 3650'
                    + ' -reqexts v3_req -extensions v3_ca',
                ]
            )  # yapf: disable

        with tempdir() as d, cd(d):
            if ca_key_path:
                ca_key = ca_key_path.read_text()
            else:
                ca_key_path = Path('ca.key')
                ca_key = check_output(
                    ['docker', 'run', '--rm', 'alpine/openssl', 'genrsa', '2048'],
                    nostderr=True,
                )
                ca_key_path.write_text(ca_key)
            if not ca_crt_path:
                ca_crt_path = Path('ca.crt')
                ca_crt = generate_certificate(ca_key)
                ca_crt_path.write_text(ca_crt)

            install_certificate_pair(ca_key_path, ca_crt_path)

    if config.kubectl.get('clusterissuer', 'local', 'cert-manager'):
        LOGGER.debug('Already have a cluster issuer with name local')
    else:
        with temporary_file() as f:
            f.write(cluster_issuer.encode('utf8'))
            f.close()
            config.kubectl.call(['apply', '-n', 'cert-manager', '-f', f.name])
        retries = 5
        wait_time = 5
        while not config.kubectl.get('secret', secret_name, 'cert-manager') and retries:
            time.wait(wait_time)
            retries -= 1
            wait_time *= 1.5
        if not retries:
            LOGGER.warning('The secret was not created after waiting for a long time.')


def _get_local_certificate(name, namespace):
    secrets = config.kubectl.get('secret', name, namespace)
    if not secrets:
        LOGGER.error('I could not find the secret'
                     f' {name} in the namespace {namespace}.'
                     ' Did you run the command'
                     ' `clk k8s cert-manager generate-certificate-authority`?')
        exit(1)
    return base64.b64decode(secrets[0]['data']['tls.crt'])


@cert_manager.command(flowdepends=['k8s.cert-manager.generate-certificate-authority'])
@option(
    '--secret-name',
    default='ca-key-pair',
    help='The secret name to pull as a certificate.',
)
@option(
    '--namespace',
    default='cert-manager',
    help='The namespace from which you wanna pull the certificate.',
)
def dump_local_certificate(secret_name, namespace):
    """Expose the local certificate to import in your browser

    See it in more detail using
    clk k8s cert-manager dump-local-certificate | openssl x509 -in i -text
    """

    click.echo(_get_local_certificate(secret_name, namespace))


@cert_manager.command(flowdepends=['k8s.cert-manager.generate-certificate-authority'])
@option(
    '--client',
    type=click.Choice([
        'webkit',
        'mozilla',
        'qutebrowser',
        'firefox',
        'chrome',
        'brave',
        'chromium',
        'all',
        'browsers',
        'ca-certificates',
    ]),
    default='browsers',
    help=('Install the certificate for the given client.'
          ' Use all to install for all of them.'
          ' Use browsers to install only for the web browsers.'),
)
@option(
    '--secret-name',
    default='ca-key-pair',
    help='The secret name to pull as a certificate.',
)
@option(
    '--namespace',
    default='cert-manager',
    help='The namespace from which you wanna pull the certificate.',
)
@option(
    '--type',
    type=click.Choice(['CA', 'Peer']),
    help='Only needed by certutil',
    default='CA',
)
@option(
    '--output-file',
    type=Path,
    help='Where to save certificates',
)
def install_local_certificate(client, secret_name, namespace, type, output_file):
    """Install the local certificate in a way webkit browsers will find it"""
    certutil = which('certutil')
    security = which('security')
    update_ca_certificates = which('update-ca-certificates')
    os_name = platform.system().lower()

    if os_name == 'linux':
        if certutil is None and client in (
                'webkit',
                'mozilla',
                'qutebrowser',
                'firefox',
                'chrome',
                'brave',
                'chromium',
                'all',
                'browsers',
        ):
            LOGGER.error('You have to install certutil to use this command.'
                         ' Hint: sudo apt install libnss3-tools')
            exit(1)
        if update_ca_certificates is None and client == 'ca-certificates':
            LOGGER.error('You have to install ca-certificates to use this command.'
                         ' Hint: sudo apt install ca-certificates')
            exit(1)
    elif os_name == 'darwin':  # macOS
        if security is None:
            LOGGER.error('The "security" command is missing.'
                         ' This is unusual as "security" is built into macOS.'
                         ' Please ensure your system is properly configured.')
            exit(1)
    else:
        raise NotImplementedError(f'Operating system not supported {os_name}, supported systems are: darwin, linux')

    cert = _get_local_certificate(secret_name, namespace)

    with temporary_file() as f:
        f.write(cert)
        f.close()
        did_something = False
        if os_name == 'darwin':
            LOGGER.info('I need your sudo password to use security to install the local certificate.'
                        ' I cannot install it only for the current user because chrome would'
                        ' not accept it that way (at least, this is what "they" told me...).')
            silent_call([
                'sudo',
                security,
                'add-trusted-cert',
                '-d',
                '-r',
                'trustRoot',
                '-k',
                '/Library/Keychains/System.keychain',
                f.name,
            ])
            did_something = True
        else:

            def install(directory):
                name = f'local-cluster-as-{type}'
                while name in check_output([
                        certutil,
                        '-d',
                        f'sql:{directory}/',
                        '-L',
                ]):
                    silent_call([
                        certutil,
                        '-d',
                        f'sql:{directory}/',
                        '-D',
                        '-n',
                        name,
                    ])
                silent_call([
                    certutil,
                    '-d',
                    f'sql:{directory}/',
                    '-A',
                    '-n',
                    name,
                    '-t',
                    f'{"C" if type == "CA" else "P"},,',
                    '-i',
                    f.name,
                ])

            if client in (
                    'webkit',
                    'chrome',
                    'brave',
                    'qutebrowser',
                    'chromium',
                    'all',
                    'browsers',
            ):
                install(f"{os.environ['HOME']}/.pki/nssdb")
                did_something = True
            if client in ('mozilla', 'firefox', 'all', 'browsers'):
                # https://stackoverflow.com/questions/1435000/programmatically-install-certificate-into-mozilla
                for directory, _, filenames in os.walk(Path(os.environ['HOME']) / '.mozilla'):
                    if 'cert9.db' in filenames:
                        install(directory)
                did_something = True
            if client in ('ca-certificates', 'all'):
                call((['sudo'] if os.getuid() != 0 else []) + ['mkdir', '-p', '/usr/local/share/ca-certificates/mine'])
                call((['sudo'] if os.getuid() != 0 else []) +
                     ['cp', f.name, '/usr/local/share/ca-certificates/mine/mine.crt'])
                call((['sudo'] if os.getuid() != 0 else []) + [update_ca_certificates])
                did_something = True
        if not did_something:
            raise NotImplementedError(f'Sounds like we did not actually deal with the client {client}')

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_bytes(cert)


class SilentCallFailed(Exception):

    def __init__(self, content):
        super().__init__()
        self.content: str = content


def _silent_call(args):
    with temporary_file() as out:
        LOGGER.action('silently run: ' + ' '.join(quote(arg) for arg in args))
        process = subprocess.Popen(args, stdout=out, stderr=out)
        res = process.wait()
        out.flush()
        if res:
            content = read(out.name)
            LOGGER.error(content)
            raise SilentCallFailed(content)


def silent_call(args):
    try:
        _silent_call(args)
    except SilentCallFailed:
        exit(5)


def silent_check_output(args):
    with temporary_file() as out:
        try:
            return check_output(args, stderr=out)
        except Exception as e:
            out.flush()
            LOGGER.error(read(out.name))
            raise e


@k8s.command(flowdepends=['k8s.wait-ready'], handle_dry_run=True)
@option(
    '--version',
    default=f'v{INGRESS_NGINX_VERSION}',
    help='The version of ingress-nginx chart to install',
)
@option('--timeout', help='Timeout before considering the installation as failing')
@flag('--force', help='Install even if already present')
def install_ingress_controller(version, force, timeout):
    """Install an ingress (ingress-nginx) in the current cluster"""
    helm_args = [
        '--repo',
        'https://kubernetes.github.io/ingress-nginx',
        '--set',
        'rbac.create=true',
        '--set',
        'controller.extraArgs.enable-ssl-passthrough=',
        '--set',
        'controller.ingressClassResource.default=true',
    ]
    if config.k8s.distribution == 'kind':
        helm_args += [
            '--set',
            'controller.service.type=NodePort',
            '--set',
            'controller.hostPort.enabled=true',
        ]  # yapf: disable
    if timeout:
        helm_args += ['--timeout', timeout]
    HelmApplication('ingress', 'ingress-nginx', version).install(force, helm_args)


@k8s.command(flowdepends=['k8s.create-cluster'], handle_dry_run=True)
@option(
    '--version',
    default=f'v{RELOADER}',
    help='The version of reloader chart to install',
)
@flag('--force', help='Install even if already present')
def install_reloader(version, force):
    """Install a reloader in the current cluster"""
    HelmApplication('reloader', 'reloader', version).install(
        force,
        [
            '--repo',
            'https://stakater.github.io/stakater-charts',
        ],
    )


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
@argument(
    'ip',
    default='',
    help=('The IP address for this domain'
          ' (default to guess from the current docker env, most likely 172.17.0.1)'),
)
@flag('--reset', help='Remove previous domains set by this command')
@option('--other-domain', multiple=True, help='Some other domain to associate with this IP address')
def add_domain(domain, ip, reset, other_domain):
    """Add a new domain entry in K8s dns"""
    import yaml

    ip = ip or config.k8s.host_ip
    if config.k8s.distribution == 'kind':
        coredns_conf = config.kubectl.output(['get', 'cm', 'coredns', '-n', 'kube-system', '-o', 'yaml'])
        coredns_conf = yaml.load(coredns_conf, Loader=yaml.FullLoader)
        update = False
        watermark = 'LINE ADDED BY CLK K8S'
        if reset:
            new_value = '\n'.join(
                [line for line in coredns_conf['data']['Corefile'].splitlines() if not line.endswith(watermark)])
            if coredns_conf['data']['Corefile'] != new_value:
                coredns_conf['data']['Corefile'] = new_value
                update = True
        if 'hosts {' not in coredns_conf['data']['Corefile']:
            data = """
        hosts {
            fallthrough
        }
            """
            last_bracket_index = coredns_conf['data']['Corefile'].rindex('}')
            coredns_conf['data']['Corefile'] = (coredns_conf['data']['Corefile'][0:last_bracket_index] + data + '\n}\n')
            update = True
        for domain_ in [domain] + list(other_domain):
            data = f'{ip} {domain_} # {watermark}'

            header, hosts, footer = re.match(
                r'^(.+hosts \{\n)([^}]*?\n?)(\s+fallthrough\s+\}.+)$',
                coredns_conf['data']['Corefile'],
                re.DOTALL,
            ).groups()

            if f'{data}\n' not in hosts:
                update = True
                coredns_conf['data']['Corefile'] = (header + hosts + '\n' + f'            {data}\n' + footer)

        if update:
            with temporary_file() as f:
                f.write(yaml.dump(coredns_conf).encode('utf8'))
                f.close()
                config.kubectl.call(['apply', '-n', 'kube-system', '-f', f.name])
                config.kubectl.call([
                    'rollout',
                    'restart',
                    '-n',
                    'kube-system',
                    'deployment/coredns',
                ])
    else:
        raise click.ClickException('Unsupported distribution')


@k8s.flow_command(
    flowdepends=[
        'k8s.cert-manager.generate-certificate-authority',
        'k8s.install-metrics-server',
        'k8s.install-reloader',
        'k8s.network-policy.install',
        'k8s.setup-credentials',
    ],
    handle_dry_run=True,
)  # yapf: disable
def flow():
    """Run the full k8s setup flow"""
    if not config.dry_run:
        LOGGER.status('Everything worked well. Now enjoy your new cluster ready to go!')


@k8s.command()
@argument(
    'target',
    type=click.Choice(['cluster', 'registry', 'all']),
    default='all',
    help='What should removed',
)
def remove(target):
    """Remove the k8s cluster"""
    if config.k8s.distribution == 'kind':
        if target in ['all', 'cluster']:
            silent_call([
                str(Kind.program_path),
                'delete',
                'cluster',
                '--name',
                CLUSTER_NAME,
            ])
        if target in ['all', 'registry']:
            reg_name = f'{config.k8s.distribution}-registry'
            if (reg_name in check_output(split('docker ps --format {{.Names}}')).split()):
                silent_call(['docker', 'kill', reg_name])
                silent_call(['docker', 'rm', reg_name])

    else:
        raise click.ClickException('Unsupported distribution')


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

    @staticmethod
    def compute_short_name(metadata):
        return f'{metadata["name"]}'

    @property
    def archive_name(self):
        return self.compute_name(self.index) + '.tgz'

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
        deps = Counter([(
            dependency['name'],
            dependency['version'],
            dependency.get('alias'),
        ) for dependency in self.dependencies])
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

    @staticmethod
    def make_package_reproducible(src, dest=None):
        srctar = tarfile.open(src)
        if dest is None:
            dest = src
        with tempdir() as d:
            src = Path(d) / 'tmp.tgz'
            tmpgz = gzip.GzipFile(src, 'wb', mtime=0)
            tmp = tarfile.open(fileobj=tmpgz, mode='w:')
            for m in sorted(srctar.getmembers(), key=lambda e: e.path):
                m.mtime = 0
                m.uid = m.gid = 0
                m.uname = m.gname = 'root'
                tmp.addfile(m, srctar.extractfile(m.name))
            tmp.close()
            tmpgz.close()
            move(src, dest)

    def package(self, directory=None):
        """Package my content into the specified directory (or by default in the current working directory)"""
        directory = directory or os.getcwd()
        LOGGER.status(f'Packaging {self.name} (from {self.location}) in {directory}')
        with tempdir() as d, cd(d):
            call([str(Helm.program_path), 'package', self.location])
            src = Path(d) / self.archive_name
            self.make_package_reproducible(src)
            dest = Path(directory) / self.archive_name
            if dest.exists():
                if (hashlib.sha256(dest.read_bytes()).hexdigest() == hashlib.sha256(src.read_bytes()).hexdigest()):
                    LOGGER.status(f'Not overwriting {dest} already with the appropriate content')
                else:
                    rm(dest)
                    move(src, dest)
            else:
                move(src, dest)

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
                    call([str(Helm.program_path), 'dependency', 'update', d])
            else:
                call([str(Helm.program_path), 'dependency', 'update', d])
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

    @classmethod
    def find_one_source(cls, dependency, subchart_sources):
        """If one subchart source is able to fulfill the dependency, return it."""
        match = [chart for chart in subchart_sources if cls.compute_name(dependency).startswith(chart.name)]
        if len(match) > 1:
            raise NotImplementedError()
        if not match:
            loose_matches = [
                chart for chart in subchart_sources
                if cls.compute_short_name(dependency).startswith(cls.compute_short_name(chart.index))
            ]
            for loose_match in loose_matches:
                LOGGER.warning(
                    f'Did not find an appropriate match for being the source of {cls.compute_name(dependency)}.'
                    f' Yet, I found {loose_match.name} in {loose_match.location}.'
                    ' It could match, if it was at the appropriate version.'
                    ' Did you forget to upgrade?')
            return None
        match = match[0]
        if cls.compute_name(dependency) != match.name:
            LOGGER.warning(f'I guessed that the provided package {match.name} (available at {match.location})'
                           f' is a good candidate to fulfill the dependency {cls.compute_name(dependency)}.'
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

            src = self.find_one_source(dependency, subchart_sources)
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
                for dependency_to_resolve in (generated_dependencies | to_resolve):
                    dependency_chart_location = (self.subcharts_dir / dependency_to_resolve)
                    temp_dependency_location = (Path(d) / Path(dependency_to_resolve).name)
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
                src = self.find_one_source(subchart.index, subchart_sources)
                if src is not None:
                    LOGGER.status(f'Substituting {subchart.location} by the source {src.name} from {src.location}')
                    rm(subchart.location)
                    copy(src.location, subchart.location)
                    updated = True
                else:
                    updated = (subchart.resolve_subcharts(subchart_sources=subchart_sources) or updated)
        return updated

    def clean_dependencies(self):
        """Remove any archive in the subcharts that is not fulfilling a
        dependency"""
        if not self.subcharts_dir.exists():
            return
        for file in self.subcharts_dir.iterdir():
            name = file.name[:-len('.tgz')]
            if name not in self.actual_dependencies:
                LOGGER.status(f'Removing {file}, not an actual dependency')
                rm(file)

    def __repr__(self):
        return f"<{self.__class__.__name__}('{self.location}')>"


@k8s.group()
def helm():
    """Commands to play with helm"""


@helm.command()
@argument('package', help='The package to make reproducible')
@option(
    '--output',
    help='Where to put the result, defaults to overwrite the package',
)
def make_package_reproducible(package, output):
    """Read a package generated via helm package and rewrite it so that it is bitwise reproducible

    That means that with the same sources, the hash of the resulting package
    will always be the same, even though "helm package" generates packages that
    have different hashes.

    This allows to take advantage of the deduplication feature of content
    addressable stuffs, like the OCI repositories.

    This command is useful until https://github.com/helm/helm/issues/3612 is fixed.

    It creates a tar.gz with the files sorted, all the mtimes set to 0 and the
    user and group set to root, following the lead from
    https://github.com/MuxZeroNet/reproducible, itself linking toward
    https://reproducible-builds.org/docs/archives/ .

    """
    Chart.make_package_reproducible(package, output)


@helm.command()
@option('--force/--no-force', '-f', help='Force update')
@option(
    '--touch',
    '-t',
    help='Touch this file or directory when update is complete',
)
@option(
    '--experimental-oci/--no-experimental-oci',
    default=True,
    help='Activate experimental OCI feature',
)
@option(
    'subchart_sources',
    '--package',
    '-p',
    multiple=True,
    type=Chart,
    help=('Directory of a helm package that can be used to override the dependency fetching mechanism'),
)
@option(
    '--remove/--no-remove',
    default=True,
    help='Remove extra dependency that may still be there',
)
@flag(
    '--uncompress',
    help=('Also leave out an uncompressed version.'
          ' Ideal for grepping into them.'),
)
@argument('chart', default='.', type=Chart, required=False, help='Helm chart path')
def dependency_update(chart, force, touch, experimental_oci, subchart_sources, remove, uncompress):
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

    That way, you simply have to run helm dependency-update --package C A and
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


@helm.command(ignore_unknown_options=True)
@argument('args', nargs=-1, help='Helm args')
def template(args):
    """Run `helm template`, so that you can easily add parameters to it"""
    call([str(Helm.program_path), 'template'] + list(args))


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
    k8s registry-login` in this command.

    You might also want to use `clk k8s cert-manager install-local-certificate`
    to make sure your local browser will be able to connect to the cluster.

    Therefore, a good default could be to do in your project `clk alias set
    k8s.setup-credentials k8s.docker-credentials
    k8s.cert-manager.install-local-certificate`

    This is not the default because I believe this depends too much on the
    project you are working on.

    """
    LOGGER.debug('No credentials added in the cluster.'
                 ' You might want to customize this to automatically'
                 ' setup your credentials. See `clk k8s setup-credentials --help`'
                 ' for more information.')


class DockerRegistrySecretName(DynamicChoice):

    def choices(self):
        return [
            get_resource_name(secret)
            for secret in config.kubectl.json(['get', 'secrets'])['items']
            if get_resource_name(secret).endswith('-registry')
        ]

    def convert(self, value, param, ctx):
        if ctx.resilient_parsing:
            return value
        choices = self.choices()
        if value not in choices:
            self.fail(
                ('invalid choice: %s. (choose from %s, or create the docker-registry secret "%s" in your kubernetes'
                 ' cluster)') % (value, ', '.join(choices), value),
                param,
                ctx,
            )
        return DynamicChoice.convert(self, value, param, ctx)


@k8s.command(flowdepends=['k8s.registry-login'])
@option('--docker-login/--no-docker-login', '-d', help='Also log into docker')
@option('--helm-login/--no-helm-login', '-h', help='Also log into helm')
@option(
    '--export-password',
    '-p',
    help='Export the passwords that directory, with the registry host as name',
)
@argument(
    'secret',
    help='Name of the k8s secret to use',
    type=DockerRegistrySecretName(),
)
def docker_credentials(docker_login, helm_login, secret, export_password):
    """Extract the docker credentials from a k8s secret"""
    creds = config.kubectl.output([
        'get',
        'secret',
        secret,
        '--template',
        '{{index .data ".dockerconfigjson" | base64decode }}',
    ])
    creds = json.loads(creds)
    for registry, values in creds['auths'].items():
        if docker_login:
            check_output([
                'docker',
                'login',
                registry,
                '-u',
                values['username'],
                '-p',
                values['password'],
            ])
        if helm_login:
            with updated_env(HELM_EXPERIMENTAL_OCI='1'):
                check_output([
                    str(Helm.program_path),
                    'registry',
                    'login',
                    registry,
                    '-u',
                    values['username'],
                    '-p',
                    values['password'],
                ])
    if export_password:
        makedirs(export_password)
        for registry, values in creds['auths'].items():
            f_path = f'{export_password}/{registry}'
            if (not os.path.exists(f_path) or read(f_path) != values['password']):
                with open(f_path, 'w') as f:
                    LOGGER.action(f'writing to {f_path}')
                    f.write(values['password'])
    print(json.dumps(creds['auths']))


_features = {
    'kind': {
        'local_registry': False,
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
@argument(
    'keys',
    type=click.Choice(list(_features['kind'].keys())),
    nargs=-1,
    help='Only display these key values. If no key is provided, all the key values are displayed',
)
def features(fields, format, keys, set_key):
    """Show supported features for the current distribution"""
    for set_key_item in set_key:
        key, value = set_key_item
        _features[config.k8s.distribution][key] = value
    if config.k8s.distribution == 'kind':
        reg_name = f'{config.k8s.distribution}-registry'
        _features[config.k8s.distribution]['local_registry'] = (reg_name in check_output(
            split('docker ps --format {{.Names}}')).split())
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


@k8s.group()
def _network_policy():
    'Play with network policies'


@_network_policy.command(flowdepends=['k8s.create-cluster'], handle_dry_run=True)
@option(
    '--strict/--permissive',
    default=True,
    help='Whether the network policy is permissive or strict',
)
@flag('--force', help='Upgrade them if already installed')
def __install(strict, force):
    """Isolate the default namespace from the rest"""
    if config.dry_run:
        LOGGER.info('(dry-run) run kubectl apply to install some network policies. '
                    ' Take a look at the code to understand what is installed exactly.')
        return
    install_them = True
    name = 'deny-from-other-namespaces'
    if config.kubectl.get('NetworkPolicy', name):
        LOGGER.debug(f'A network policy already exists with name {name}')
        install_them = force
    if install_them:
        content = network_policy
        if not strict:
            content += extra_network_policy
        with temporary_file(content=content) as f:
            config.kubectl.call(['apply', '-f', f.name])


@k8s.group()
def tilt():
    'Commands to deal with tilt'


@tilt.command(flowdepends=['k8s.flow'], ignore_unknown_options=True)
@argument('tiltfile-args', help='Arguments to give tilt', nargs=-1)
@option('--tilt-arg', help='Arguments to give tilt', multiple=True)
@flag('--open', help='Open the url in a browser')
@flag(
    '--use-context/--dont-use-context',
    help='Try to use the appropriate context before running tilt',
)
@option(
    '--label',
    help='What labels to select',
    multiple=True,
)
@option('--namespace', help='Given to tilt', default='default')
def _run(open, use_context, tilt_arg, tiltfile_args, label, namespace):
    'Run whatever is needed to run tilt'
    root = Path('.').absolute()
    tiltfile_name = 'Tiltfile'
    while root.parent != root and not (root / tiltfile_name).exists():
        root = root.parent
    if not (root / tiltfile_name).exists():
        raise click.UsageError(f'I looked for a file called {tiltfile_name} in this'
                               ' directory and all its parents, without finding any.')
    if open:
        Popen([os.environ['BROWSER'], 'http://localhost:10350'])
    if use_context:
        context = {
            'kind': f'kind-{CLUSTER_NAME}',
        }[config.k8s.distribution]
        silent_call([str(Kubectl.program_path), 'config', 'use-context', context])
    tiltfile_args = list(tiltfile_args)
    tiltfile_args += ['--clear-enabled-resources']
    tilt_arg = list(tilt_arg)
    tilt_arg += ['--namespace', namespace]
    process = Popen(
        [
            str(Tilt.program_path),
            'up',
        ] + split(' '.join(tilt_arg)) + ['--'] + tiltfile_args,
        cwd=root,
    )
    LOGGER.info('Now, waiting for tilt to be ready')
    time.sleep(2)
    call(['tilt', 'wait', '--timeout=3m', '--for=condition=Ready', 'uiresources/(Tiltfile)'])
    if label:
        args = ['tilt', 'enable', 'uncategorized']
        for label_ in label:
            args += ['-l', label_]
        call(args)
    process.wait()


class NamespaceNameType(DynamicChoice):

    def choices(self):
        return [get_resource_name(item) for item in config.kubectl.json(['get', 'namespaces'], internal=True)['items']]


@k8s.group()
@option(
    '--namespace',
    help='The namespace to share',
    default='default',
    type=NamespaceNameType(),
)
@option(
    '--sa-name',
    help='The name of the service account created',
    default='shared-access',
)
@option('--role-name', help='The name of the role to create', default='shared-role')
def share_access(namespace, sa_name, role_name):
    """Some commands to ease sharing access to a cluster

    Inspired by https://computingforgeeks.com/restrict-kubernetes-service-account-users-to-a-namespace-with-rbac/
    """
    config.namespace = namespace
    config.sa_name = sa_name
    config.override_env['NAMESPACE'] = namespace
    config.override_env['SA'] = sa_name
    config.override_env['ROLE'] = role_name
    config.init()


@share_access.command(flowdepends=['k8s.share-access.bind-role'])
@argument('output', help='Where to write the content', type=Path)
def write_kubectl_config(output):
    """Write the config that gives the shared access"""
    item = [
        item for item in config.kubectl.json(['-n', config.namespace, 'get', 'secret'])['items']
        if item['metadata'].get('annotations', {}).get('kubernetes.io/service-account.name') == config.sa_name
    ][0]
    sa_token = base64.b64decode(item['data']['token']).decode()
    ca_crt = item['data']['ca.crt']

    current_conf = config.kubectl.json(['config', 'view', '--raw'])
    contexts = [context for context in current_conf['contexts'] if context['name'] == config.kubectl.context]
    contexts[0]['context']['user'] = config.sa_name
    assert len(contexts) == 1
    clusters = [cluster for cluster in current_conf['clusters'] if cluster['name'] == contexts[0]['context']['cluster']]
    new_conf = {
        'kind': 'Config',
        'apiVersion': 'v1',
        'preferences': {},
        'clusters': clusters,
        'users': [
            {
                'name': config.sa_name,
                'user': {
                    'token': sa_token,
                    'client-key-data': ca_crt,
                },
            },
        ],
        'contexts': contexts,
        'current-context': config.kubectl.context,
    }
    output.write_text(yaml.dump(new_conf))


@k8s.command(handle_dry_run=True)
@argument(
    'new-config',
    help='The new config used to update the current one',
    type=Path,
)
@flag(
    '--keep-current-context/--overwrite-current-context',
    help='Whether to use the new context or not',
)
@flag('--force', help='Force updating in case of conflicts')
@option(
    '--kube-config-location',
    help='What file to update',
    default=Path('~/.kube/config').expanduser(),
    type=Path,
)
def update_config(new_config, keep_current_context, force, kube_config_location):
    """Get the values of the new config and put then in the current config"""
    config = yaml.safe_load(kube_config_location.read_text())
    given_config = yaml.safe_load(new_config.read_text())
    for key in 'clusters', 'users', 'contexts':
        given_values = {value['name']: value for value in given_config[key]}
        values = {value['name']: value for value in config[key]}
        if set(values).intersection(set(given_values)) and not force:
            raise click.UsageError(
                "I won't merge them because those values are in both the new and the old config"
                f" {key} -> {', '.join(name for name in set(values).intersection(set(given_values)))}"
                '. Hint (use --force to do it anyway)')
        new_values = given_config[key]
        for name in set(values) - set(given_values):
            new_values.append(values[name])
        config[key] = new_values
    if not keep_current_context:
        config['current-context'] = given_config['current-context']
    createfile(kube_config_location, yaml.safe_dump(config), force=True)


class PVCType(DynamicChoice):

    def choices(self):
        return [pvc['metadata']['name'] for pvc in config.kubectl.get('pvc')]


@k8s.group()
def pv():
    'Manipulate persistent volumes'


@pv.command()
@argument('pvc-name', help='Name of the PV to attach to', type=PVCType())
@argument(
    'command',
    help='The optional command to run once attached to the volume',
    nargs=-1,
)
def attach(pvc_name, command):
    'Run a temporary pod to see the content of a pv'
    command = list(command) or ['sh']
    with temporary_file(suffix='.yaml') as f:
        podname = f'dataaccess-{pvc_name}'
        content = f"""apiVersion: v1
kind: Pod
metadata:
  name: {podname}
  labels:
    dataccess-{pvc_name}: "true"
spec:
  containers:
  - name: alpine
    image: alpine:latest
    command: ['sleep', 'infinity']
    volumeMounts:
    - name: {pvc_name}
      mountPath: /data
  volumes:
  - name: {pvc_name}
    persistentVolumeClaim:
      claimName: {pvc_name}"""
        LOGGER.debug(f'Creating pod with content: \n{content}')
        f.write(content.encode())
        f.close()
        LOGGER.info(f'Creating temporary pod to attach to {pvc_name}, mounted in /data')
        config.kubectl.call(['apply', '-f', f.name])
        try:
            config.kubectl.call([
                'wait',
                '--for=condition=ready',
                'pod',
                '-l',
                f'dataccess-{pvc_name}=true',
            ])
            LOGGER.info(f'Running command: {" ".join(quote(arg) for arg in command)}')
            config.kubectl.call(['exec', '-i', '-t', podname, '--'] + command, silent=False)
        finally:
            LOGGER.info(f'Cleaning the temporary pod attached to this pvc {pvc_name}')
            config.kubectl.call(['delete', '--wait', '-f', f.name])


@k8s.group()
def node():
    'Play with nodes'


class NodeType(DynamicChoice):

    def choices(self):
        return [node['metadata']['name'] for node in config.kubectl.get('node')]


@node.command()
@argument('node', help='The node to connect to', type=NodeType())
def shell(node):
    'Start a shell in the node, using privilege escalation'
    name = f'node-shell-{uuid.uuid4()}'
    content = f"""apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: kube-system
  labels:
    name: {name}
spec:
  containers:
  - args:
    - -t
    - "1"
    - -m
    - -u
    - -i
    - -n
    - sleep
    - "14000"
    command:
    - nsenter
    image: docker.io/alpine:3.13
    imagePullPolicy: IfNotPresent
    name: shell
    securityContext:
      privileged: true
  nodeName: {node}
  preemptionPolicy: PreemptLowerPriority
  priority: 2000001000
  hostIPC: true
  hostNetwork: true
  hostPID: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  priorityClassName: system-node-critical
  restartPolicy: Never
  schedulerName: default-scheduler
  serviceAccount: default
  serviceAccountName: default
  terminationGracePeriodSeconds: 0
  tolerations:
  - operator: Exists
"""
    with temporary_file(suffix='.yaml') as f:
        f.write(content.encode())
        f.close()
        config.kubectl.call(['apply', '-f', f.name])
        try:
            config.kubectl.call([
                '-n',
                'kube-system',
                'wait',
                '--for=condition=ready',
                'pod',
                '-l',
                f'name={name}',
            ])
            config.kubectl.call(
                ['-n', 'kube-system', 'exec', '-i', '-t', name, '--', 'sh'],
                silent=False,
            )
        finally:
            LOGGER.info(f'Cleaning the temporary pod attached to this node {node}')
            config.kubectl.call(['delete', '--wait', '-f', f.name])


class TiltLabelType(DynamicChoice):

    @staticmethod
    @cache_disk(expire=60)
    def get_labels():
        resources = json.loads(check_output([
            'tilt',
            'get',
            'uiresources',
            '--output',
            'json',
        ]))
        return {label for item in resources['items'] for label in item['metadata'].get('labels', [])}

    def choices(self):
        return self.get_labels()


class TiltConfig:
    pass


@tilt.group()
@option(
    '--label',
    type=TiltLabelType(),
    help='What labels to select',
    multiple=True,
    expose_class=TiltConfig,
)
@option(
    '--but',
    type=TiltLabelType(),
    help='Exclude those',
    multiple=True,
    expose_class=TiltConfig,
)
@flag(
    '--all',
    help='Select all of them',
    expose_class=TiltConfig,
)
def resources():
    'Select the resources that match the given criteria'
    if config.tilt.all:
        config.tilt.label = TiltLabelType.get_labels()
    config.tilt.label = [label for label in config.tilt.label if label not in config.tilt.but]


def able_command(direction):

    def able():
        args = ['tilt', direction]
        for label in config.tilt.label:
            args += ['-l', label]
        call(args)

    resources.command(name=direction, help=f'{direction.capitalize()} the selected resources')(able)


able_command('disable')
able_command('enable')


@resources.command()
def only():
    'Enable ONLY those resources'
    args = ['tilt', 'disable']
    for label in TiltLabelType.get_labels():
        args += ['-l', label]
    call(args)
    run(['k8s', 'tilt', 'resources', 'enable'])


class K8sgoConfig:
    pass


class K8sContextType(DynamicChoice):

    def choices(self):

        @cache_disk(expire=60)
        def k8s_contexts():
            return check_output(['kubectl', 'config', 'get-contexts', '-o', 'name']).splitlines()

        return k8s_contexts()


class K8sNamespaceType(DynamicChoice):

    def choices(self):

        @cache_disk(expire=60)
        def k8s_namespace(context):
            return [
                '/'.join(name.split('/')[1:]) for name in check_output(
                    ['kubectl', '--context', context, 'get', 'namespaces', '-o', 'name']).splitlines()
            ]

        return k8s_namespace(config.k8sgo.context)


@k8s.command()
@argument('context', help='Use that context', type=K8sContextType(), expose_class=K8sgoConfig)
@argument('namespace',
          help='Use that namespace in that context',
          default='default',
          type=K8sNamespaceType(),
          expose_class=K8sgoConfig)
def go():
    """Configure k8s to use that context and that namespace"""
    call(['kubectl', 'config', 'use-context', config.k8sgo.context])
    call(['kubectl', 'config', 'set-context', config.k8sgo.context, '--namespace', config.k8sgo.namespace])
