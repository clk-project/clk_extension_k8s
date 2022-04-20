VERSION 0.6
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

check-quality:
    FROM +pre-commit-base
    COPY --dir .pre-commit-config.yaml .
    COPY +pre-commit-cache/cache $HOME/.cache/pre-commit
    COPY . .
    RUN pre-commit run -a

test:
    FROM earthly/dind:ubuntu # this one currently ships with python3.8
    ARG shell=bash
    RUN python3 --version | grep 'Python 3.8' # make sure we have python 3.8
    # RUN apk add --update git
    # ARG shell=sh
    RUN apt-get update && apt-get install --yes git wget python3-distutils
    DO e+USE_USER
    RUN wget -O - https://clk-project.org/install.sh | env CLK_EXTENSIONS=k8s ${shell}
    ARG distribution=kind
    RUN clk k8s --distribution=$distribution install-dependency all
    USER root
    COPY hello hello
    WITH DOCKER
        RUN clk k8s --distribution=$distribution flow --flow-after k8s.install-dependency.all \
        && helm upgrade --install hello hello \
        && while ! kubectl get pod | grep -q Running;do echo wait for pod;sleep 2;done \
        && echo "A pod is running!"
    END

test-all:
    BUILD +check-quality
    BUILD +test --distribution=kind
    BUILD +test --distribution=k3d
