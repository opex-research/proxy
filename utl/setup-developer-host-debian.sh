#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd ${SCRIPT_DIR}

# update and upgrade host apt environment
sudo apt-get update
sudo apt-get -y upgrade
sudo apt-get -y install curl

# install dependencies
sudo apt-get -y install build-essential cmake git libssl-dev sudo python3 vim libgmp3-dev libprocps-dev openjdk-17-jdk junit4 python3-markdown libboost-program-options-dev pkg-config docker.io

# install golang
sudo rm -rf /usr/local/go
curl -LO https://go.dev/dl/go1.19.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf ./go1.19.3.linux-amd64.tar.gz
rm ./go1.19.3.linux-amd64.tar.gz
