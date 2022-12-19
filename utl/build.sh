#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd ${SCRIPT_DIR}

# building libsnark
cd ${SCRIPT_DIR}/..
cd ./dependencies/libsnark-demo
mkdir build
cd build
cmake .. -DMULTICORE=ON
make
