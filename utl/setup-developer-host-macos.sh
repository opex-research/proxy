#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd ${SCRIPT_DIR}

# TODO: add macOS setup to tun Docker

# install homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

## install useful tools
brew install cmake
brew install go
brew install gmp
brew install boost
brew install gcc
brew install openssl

## TODO: check if necessary
#brew install python-markdown
