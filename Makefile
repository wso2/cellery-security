# --------------------------------------------------------------------
# Copyright (c) 2019, WSO2 Inc. (http://wso2.com) All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------

PROJECT_ROOT := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
PROJECT_ENVOY_FILTER_ROOT := $(PROJECT_ROOT)/components/envoy-oidc-filter
PROJECT_PKG := github.com/cellery-io/mesh-controller
BUILD_DIRECTORY := build
BUILD_ROOT := $(PROJECT_ENVOY_FILTER_ROOT)/$(BUILD_DIRECTORY)
GO_FILES		= $(shell find . -type f -name '*.go' -not -path "./vendor/*")
GIT_REVISION := $(shell git rev-parse --verify HEAD)

OIDC_FILTER_NAME := envoy-oidc-filter

VERSION ?= $(GIT_REVISION)

DOCKER_REPO ?= wso2cellery
DOCKER_IMAGE_TAG ?= $(VERSION)

.PHONY: build-java-components
build-java-components:
	cd ./components; \
	mvn clean install;

.PHONY: build-all
build-all: build-java-components docker-push

.PHONY: docker-push
docker-push: docker-push.sts-server-docker docker-push.envoy-oidc-filter

.PHONY: docker.sts-server-docker
docker.sts-server-docker:
	[ -d "docker/sts/target" ] || mvn initialize -f docker/sts/pom.xml
	cd docker/sts; \
	docker build -t ${DOCKER_REPO}/cell-sts:${DOCKER_IMAGE_TAG} .

.PHONY: docker-push.sts-server-docker
docker-push.sts-server-docker: docker.sts-server-docker
	docker push ${DOCKER_REPO}/cell-sts:${DOCKER_IMAGE_TAG}

.PHONY: build.envoy-oidc-filter
build.envoy-oidc-filter:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BUILD_ROOT)/$(OIDC_FILTER_NAME) -x $(PROJECT_ENVOY_FILTER_ROOT)

.PHONY: docker.envoy-oidc-filter
docker.envoy-oidc-filter: build.envoy-oidc-filter
	docker build -f $(PROJECT_ROOT)/docker/$(OIDC_FILTER_NAME)/Dockerfile $(BUILD_ROOT) -t $(DOCKER_REPO)/$(OIDC_FILTER_NAME):$(DOCKER_IMAGE_TAG)

.PHONY: docker-push.envoy-oidc-filter
docker-push.envoy-oidc-filter: docker.envoy-oidc-filter
	docker push $(DOCKER_REPO)/$(OIDC_FILTER_NAME):$(DOCKER_IMAGE_TAG)

.PHONY: code.format
code.format: tools.goimports
	@goimports -local $(PROJECT_PKG) -w -l $(GO_FILES)

.PHONY: code.format-check
code.format-check: tools.goimports
	@goimports -local $(PROJECT_PKG) -l $(GO_FILES)

.PHONY: tools tools.goimports

tools: tools.goimports

tools.goimports:
	@command -v goimports >/dev/null ; if [ $$? -ne 0 ]; then \
		echo "goimports not found. Running 'go get golang.org/x/tools/cmd/goimports'"; \
		go get golang.org/x/tools/cmd/goimports; \
	fi
