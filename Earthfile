VERSION 0.7
IMPORT github.com/Konubinix/Earthfile AS e

pre-commit-base:
    FROM python:slim
    RUN apt-get update && apt-get install --yes git
    DO e+USE_USER
    RUN python3 -m pip install pre-commit
    WORKDIR /app

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
    FROM earthly/dind:ubuntu-20.04 # this one currently ships with python3.8
    ARG shell=bash
    RUN python3 --version | grep 'Python 3.8' # make sure we have python 3.8
    # RUN apk add --update git
    # ARG shell=sh
    RUN apt-get update && apt-get install --yes git wget python3-distutils
    DO e+USE_USER
    ARG from=source
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
    WITH DOCKER
        RUN --no-cache bash test.sh
    END
test-all:
    BUILD +check-quality
    BUILD +test --distribution=kind
    BUILD +test --distribution=k3d
