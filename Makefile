# enable multicore make, taken from: https://stackoverflow.com/a/51149133
NPROCS = $(shell grep -c 'processor' /proc/cpuinfo)
MAKEFLAGS += -j$(NPROCS)

all:
	@echo "This is a dummy to prevent running make without explicit target!"

init: clean setupDeveloperHost
	git submodule update --init --recursive

setupDeveloperHost:
	./setup-developer-host-common.sh

clean:
	# TODO: remove build outputs
	rm -rf ./dependencies/jsnark-demo/JsnarkCircuitBuilder/bin
	rm -rf ./dependencies/libsnark-demo/build
	rm -rf origo
	$(MAKE) -C server/ clean
	$(MAKE) -C proxy/ clean
	$(MAKE) -C prover/ clean
	. ./evaluation.sh && cleanEvaluationLogs
	. ./evaluation.sh && cleanCapturedTraffic
	. ./evaluation.sh && cleanSnarkFiles

build: clean
	./utl/build.sh
	$(MAKE) -C server/ build
	$(MAKE) -C proxy/ build
	#TODO: check
	# $(MAKE) -C prover/ build
	go mod tidy
	go build -buildvcs=false .

runEvaluationLocal: build
	. ./evaluation.sh && runEvaluationLocal

buildDockerImage: clean
	sudo docker image rm origo_image || true
	sudo docker build -t origo_image -f docker/Dockerfile .

runDockerImage:
	sudo docker container rm origo_container || true
	sudo docker run --name origo_container -p 8082:8082 -it origo_image
