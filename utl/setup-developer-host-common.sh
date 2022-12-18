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

# download jar binary
cd $SCRIPT_DIR/..
cd ./dependencies/jsnark-demo/JsnarkCircuitBuilder

curl -LO https://www.bouncycastle.org/download/bcprov-jdk15on-159.jar
# TODO: remove macOS JUnit fix
# curl -LO https://search.maven.org/remotecontent?filepath=junit/junit/4.13.2/junit-4.13.2.jar
