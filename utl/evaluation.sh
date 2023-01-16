#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd ${SCRIPT_DIR}

cd ${SCRIPT_DIR}/..

###### function declarations ############

cleanEvaluationLogs()
{
  # echo "I was called as : $@"
  echo "cleaning evaluation logs"
  rm -rf log
  rm -rf proxy/service/evaluation.log
}

cleanCapturedTraffic()
{
  echo "cleaning capture traffic data"
  rm -rf local_storage
  rm -rf proxy/service/local_storage
}


runEvaluationLocal()
{
  ###### protocol evaluation  ############

  echo "start evaluation"

  # logging cleanup
  cleanEvaluationLogs
  mkdir log

  ###### local mode ######################

  # define policies to evaluate
  policyList="policy_local1 policy_local2"

  # start servers

  # Iterate the string variable using for loop
  for val in $policyList; do

    # cleaning files
    cleanCapturedTraffic
    mkdir local_storage
    mkdir -p proxy/service/local_storage

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
