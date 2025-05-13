VERSION 0.8
IMPORT github.com/Konubinix/Earthfile AS e

pre-commit-base:
    # ruamel does not provide wheels that work for alpine. Therefore we use debian here
    FROM e+debian-python-user-venv --extra_packages="git" --packages="pre-commit"

export-pre-commit-update:
    FROM +pre-commit-base
    RUN git init
    COPY --dir .pre-commit-config.yaml .
    RUN --no-cache pre-commit autoupdate
    SAVE ARTIFACT .pre-commit-config.yaml AS LOCAL .pre-commit-config.yaml

pre-commit-cache:
    FROM +pre-commit-base
    RUN git init
    COPY --dir .pre-commit-config.yaml .
    RUN pre-commit run -a
    SAVE ARTIFACT ${HOME}/.cache/pre-commit cache

quality-base:
    FROM +pre-commit-base
    COPY --dir .pre-commit-config.yaml .
    COPY +pre-commit-cache/cache $HOME/.cache/pre-commit
    COPY . .

check-quality:
    FROM +quality-base
    RUN pre-commit run -a

fix-quality:
    FROM +quality-base
    RUN pre-commit run -a || echo OK
    SAVE ARTIFACT . AS LOCAL fixed

test-base:
    FROM earthly/dind:ubuntu-24.04-docker-27.3.1-1
    ARG shell=bash
    ARG extra_packages=""
    RUN apt-get update && apt-get install --yes git wget python3-venv coreutils ${extra_packages}
    DO e+USE_USER --uid=1001
    ARG from=source
    WORKDIR /app
    RUN python3 -m venv /app/venv
    ENV PATH="/app/venv/bin:$PATH"
    RUN mkdir -p /home/sam/.local/bin/
    ENV PATH="/home/sam/.local/bin/:$PATH"
    IF [ "${from}" = "source" ]
        RUN wget -O - https://clk-project.org/install.sh | ${shell}
        COPY --dir bin python tilt-extensions clk.json version.txt /k8s/
        RUN clk extension install /k8s
    ELSE
        RUN wget -O - https://clk-project.org/install.sh | env CLK_EXTENSIONS=k8s ${shell}
    END
    ARG distribution=kind
    RUN clk k8s --distribution=$distribution install-dependency all
    RUN clk parameter set k8s.create-cluster --use-public-dns # needed to workaround image pull issues in mac->colima->docker->earthlybuildkit->docker->kind

RUN_TEST:
    FUNCTION
    ARG args # could be --debug
    USER root
    ARG distribution=kind
    ARG from=source
    WITH DOCKER
        RUN --no-cache clk ${args} k8s --distribution=$distribution flow --flow-after k8s.install-dependency.all && bash test.sh
    END
    SAVE ARTIFACT --if-exists /tmp/out AS LOCAL out/${distribution}-${from}

test:
    ARG distribution=kind
    ARG from=source
    FROM +test-base --distribution=$distribution --from=$from
    COPY hello hello
    COPY test.sh ./test.sh
    DO +RUN_TEST --distribution=$distribution --from=$from

test-all:
    BUILD +check-quality
    BUILD +test --distribution=kind

test-all-amd64:
    BUILD --platform linux/amd64 +test-all

test-all-arm64:
    BUILD --platform linux/arm64 +test-all
