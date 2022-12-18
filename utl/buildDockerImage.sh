#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd ${SCRIPT_DIR}

cd ${SCRIPT_DIR}/..
COMMIT=$(git rev-parse --verify HEAD)
sudo docker image build -f docker/Dockerfile . -t "origo-verifier:latest" -t "origo-verifier:${COMMIT}"
