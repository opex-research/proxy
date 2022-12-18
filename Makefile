# enable multicore make, taken from: https://stackoverflow.com/a/51149133
NPROCS = $(shell grep -c 'processor' /proc/cpuinfo)
MAKEFLAGS += -j$(NPROCS)

all:
	@echo "This is a dummy to prevent running make without explicit target!"

init: clean setupDeveloperHost
	git submodule update --init --recursive

setupDeveloperHost:
	$(MAKE) -C utl/ setupDeveloperHost

clean:
	# TODO: remove build outputs
	rm -rf ./dependencies/jsnark-demo/JsnarkCircuitBuilder/bin
	rm -rf ./dependencies/libsnark-demo/build
	rm -rf origo
	$(MAKE) -C proxy/ clean
	$(MAKE) -C utl/ clean

build: clean
	$(MAKE) -C utl/ build
	$(MAKE) -C proxy/ build
	go mod tidy
	go build -buildvcs=false .

buildDockerImage: clean
	$(MAKE) -C utl/ buildDockerImage

buildDockerImageClean: clean
	$(MAKE) -C utl/ buildDockerImageClean

runDockerImage:
	$(MAKE) -C utl/ runDockerImage

runEvaluationLocal: build
	$(MAKE) -C utl/ runEvaluationLocal
