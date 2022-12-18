#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd ${SCRIPT_DIR}

cd ${SCRIPT_DIR}/..
cd ./dependencies/jsnark-demo/JsnarkCircuitBuilder
mkdir bin
javac -d bin -cp /usr/share/java/junit4.jar:bcprov-jdk15on-159.jar $(find ./src/* | grep ".java$")
# TODO: remove macOS JUnit fix
# javac -d bin -cp junit-4.13.2.jar:bcprov-jdk15on-159.jar $(find ./src/* | grep ".java$")

# building libsnark
cd ${SCRIPT_DIR}/..
cd ./dependencies/libsnark-demo
mkdir build
cd build
# TODO: remove macOS fix
# cmake .. -DMULTICORE=ON -DWITH_PROCPS=OFF -DWITH_SUPERCOP=OFF
cmake .. -DMULTICORE=ON
make
