VERSION 0.7
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

test:
    FROM earthly/dind:ubuntu-23.04-docker-24.0.5-1
    ARG shell=bash
    RUN apt-get update && apt-get install --yes git wget python3-distutils python3-venv
    DO e+USE_USER --uid=1001
    ARG from=source
    WORKDIR /app
    RUN python3 -m venv /app/venv
    ENV PATH="/app/venv/bin:$PATH"
    RUN mkdir -p /home/sam/.local/bin/
    ENV PATH="/home/sam/.local/bin/:$PATH"
    IF [ "${from}" = "source" ]
        RUN wget -O - https://clk-project.org/install.sh | ${shell}
        COPY --dir bin python tilt-extensions k3s-manifests clk.json version.txt /k8s/
        RUN clk extension install /k8s
    ELSE
        RUN wget -O - https://clk-project.org/install.sh | env CLK_EXTENSIONS=k8s ${shell}
    END
    ARG distribution=kind
    RUN clk k8s --distribution=$distribution install-dependency all
    # make sure the workaround about buildkit still works
    RUN clk k8s --distribution=$distribution install-dependency kubectl-buildkit
    USER root
    COPY hello hello
    COPY test.sh ./test.sh
    RUN --no-cache echo "Invalidate the cache (somehow the next one don't work)"
    ARG debug=no
    WITH DOCKER
        RUN --no-cache bash test.sh
    END

test-all:
    BUILD +check-quality
    BUILD +test --distribution=kind
    BUILD +test --distribution=k3d
