#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd ${SCRIPT_DIR}

cd ${SCRIPT_DIR}/..

###### function declarations ############

cleanEvaluationLogs()
{
  # echo "I was called as : $@"
  echo "cleaning evaluation logs"
  rm -rf proxy/service/evaluation.log
  rm -rf commands/evaluation.log
}

cleanCapturedTraffic()
{
  echo "cleaning capture traffic data"
  rm -rf proxy/service/local_storage/PublicInput.json
  rm -rf proxy/service/local_storage/ProverSentRecords.raw
  rm -rf proxy/service/local_storage/ProverSentRecords.txt
  rm -rf proxy/service/local_storage/ProverSentRecords.raw
  rm -rf proxy/service/local_storage/ProverSentRecords.txt
}

cleanSnarkFiles()
{
  echo "cleaning snark specific files"
  rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/src/examples/generators/transpiled/LocalGen.java
  rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/src/examples/generators/transpiled/PayPalGen.java
  rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/bin/examples/generators/transpiled/LocalGen.class
  rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/bin/examples/generators/transpiled/PayPalGen.class
}

runEvaluationLocal()
{
  ###### protocol evaluation  ############

  echo "start evaluation"

  # logging cleanup
  cleanEvaluationLogs

  ###### local mode ######################

  # define policies to evaluate
  policyList="policy_local1 policy_local2"

  # start servers

  # Iterate the string variable using for loop
  for val in $policyList; do

    # cleaning files
    cleanCapturedTraffic

    # clean up snark files
    cleanSnarkFiles

    # print policy name
    echo evaluate policy file: $val

    # run protocol
    ./origo proxy-start

    ./origo prover-request $val local1
    ./origo proxy-postprocess $val

    ./origo proxy-stop

    ./origo proxy-verify
  done

  echo "evaluation done"
}
