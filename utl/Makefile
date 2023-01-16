setupDeveloperHost:
	./setup-developer-host-common.sh

clean:
	. ./evaluation.sh && cleanEvaluationLogs
	. ./evaluation.sh && cleanCapturedTraffic
	. ./evaluation.sh && cleanSnarkFiles

build:
	./build.sh

buildDockerImage:
	./buildDockerImage.sh

buildDockerImageClean:
	sudo docker image rm "origo-verifier:latest" || true
	$(MAKE) -C . buildDockerImage

runDockerImage:
	sudo docker container rm "origo-verifier" || true
	sudo docker run --name "origo-verifier" -p 8082:8082 -it "origo-verifier:latest"

runEvaluationLocal:
	. ./evaluation.sh && runEvaluationLocal
