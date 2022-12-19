#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd ${SCRIPT_DIR}

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  ./setup-developer-host-debian.sh
  # TODO: implement host environment setup shell script
  export PATH=$PATH:/usr/local/go/bin
elif [[ "$OSTYPE" == "darwin"* ]]; then
  ./setup-developer-host-macos.sh
  # TODO: implement host environment setup shell script
  export JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.5
  export PATH="/opt/homebrew/opt/openssl@3/bin:$PATH"
  export CC=/opt/homebrew/bin/gcc-12
  export CXX=/opt/homebrew/bin/g++-12
else
  echo "ERROR: The host machine's OS type is not compatible with this setup routine."
fi
