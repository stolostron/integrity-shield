#
# Copyright 2020 IBM Corporation
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
#

SHELL=/bin/bash

# LOAD ENVIRNOMENT SETTINGS (must be done at first)
###########################
ifeq ($(ISHIELD_REPO_ROOT),)
$(error ISHIELD_REPO_ROOT is not set)
endif
ifeq ($(ISHIELD_ENV),)
$(error "ISHIELD_ENV is empty. Please set local or remote.")
endif
ifeq ($(ISHIELD_TEST_ENV),)
$(error "ISHIELD_TEST_ENV is empty. Please set local or remote.")
endif

include  .env
export $(shell sed 's/=.*//' .env)

ifeq ($(ENV_CONFIG),)
$(error ENV_CONFIG is not set)
endif

include  $(ENV_CONFIG)
export $(shell sed 's/=.*//' $(ENV_CONFIG))

include $(SHIELD_OP_DIR)Makefile

ifeq ($(ISHIELD_TEMP_DIR),)
TMP_DIR = /tmp/
else
TMP_DIR = $(ISHIELD_TEMP_DIR)
$(shell mkdir -p $(TMP_DIR))
endif

# CICD BUILD HARNESS
####################
ifeq ($(ISHIELD_ENV), remote)
-include $(shell curl -s -H 'Authorization: token ${GITHUB_TOKEN}' -H 'Accept: application/vnd.github.v4.raw' -L https://api.github.com/repos/open-cluster-management/build-harness-extensions/contents/templates/Makefile.build-harness-bootstrap -o .build-harness-bootstrap; echo .build-harness-bootstrap)
endif
####################

.PHONY: default
default::
	@echo "Build Harness Bootstrapped"

# Docker build flags
DOCKER_BUILD_FLAGS := --build-arg VCS_REF=$(GIT_COMMIT) $(DOCKER_BUILD_FLAGS)

# This repo is build in Travis-ci by default;
# Override this variable in local env.
TRAVIS_BUILD ?= 1

# Github host to use for checking the source tree;
# Override this variable ue with your own value if you're working on forked repo.
GIT_HOST ?= github.com/IBM

PWD := $(shell pwd)
BASE_DIR := $(shell basename $(PWD))

# Keep an existing GOPATH, make a private one if it is undefined
GOPATH_DEFAULT := $(PWD)/.go
export GOPATH ?= $(GOPATH_DEFAULT)
GOBIN_DEFAULT := $(GOPATH)/bin
export GOBIN ?= $(GOBIN_DEFAULT)
TESTARGS_DEFAULT := "-v"
export TESTARGS ?= $(TESTARGS_DEFAULT)
DEST ?= $(GOPATH)/src/$(GIT_HOST)/$(BASE_DIR)


LOCAL_OS := $(shell uname)
ifeq ($(LOCAL_OS),Linux)
    TARGET_OS ?= linux
    XARGS_FLAGS="-r"
else ifeq ($(LOCAL_OS),Darwin)
    TARGET_OS ?= darwin
    XARGS_FLAGS=
else
    $(error "This system's OS $(LOCAL_OS) isn't recognized/supported")
endif


.PHONY: config int fmt lint test coverage build build-images build-cli


config:
	@[ "${ENV_CONFIG}" ] && echo "Env config is all good" || ( echo "ENV_CONFIG is not set"; exit 1 )


############################################################
# format section
############################################################

# All available format: format-go format-protos format-python
# Default value will run all formats, override these make target with your requirements:
#    eg: fmt: format-go format-protos
fmt: format-go


format-go:
	@set -e; \
	GO_FMT=$$(git ls-files *.go | grep -v 'vendor/' | grep -v 'third_party/' | xargs gofmt -d); \
	if [ -n "$${GO_FMT}" ] ; then \
		echo "Please run go fmt"; \
		echo "$$GO_FMT"; \
		exit 1; \
	fi

############################################################
# check section
############################################################

check: lint

# All available linters: lint-dockerfiles lint-scripts lint-yaml lint-copyright-banner lint-go lint-python lint-helm lint-markdown lint-sass lint-typescript lint-protos
# Default value will run all linters, override these make target with your requirements:
#    eg: lint: lint-go lint-yaml
lint: lint-init  lint-verify lint-op-init lint-op-verify

lint-init:
	cd $(SHIELD_DIR) && golangci-lint run --timeout 5m -D errcheck,unused,gosimple,deadcode,staticcheck,structcheck,ineffassign,varcheck | tee $(TMP_DIR)lint_results_ishield.txt

lint-verify:
	$(eval FAILURES=$(shell cat $(TMP_DIR)lint_results_ishield.txt | grep "FAIL:"))
	cat  $(TMP_DIR)lint_results_ishield.txt
	@$(if $(strip $(FAILURES)), echo "One or more linters failed. Failures: $(FAILURES)"; exit 1, echo "All linters are passed successfully."; exit 0)

lint-op-init:
	cd $(SHIELD_OP_DIR) && golangci-lint run --timeout 5m -D errcheck,unused,gosimple,deadcode,staticcheck,structcheck,ineffassign,varcheck,govet | tee $(TMP_DIR)lint_results.txt

lint-op-verify:
	$(eval FAILURES=$(shell cat $(TMP_DIR)lint_results.txt | grep "FAIL:"))
	cat $(TMP_DIR)lint_results.txt
	@$(if $(strip $(FAILURES)), echo "One or more linters failed. Failures: $(FAILURES)"; exit 1, echo "All linters are passed successfully."; exit 0)


############################################################
# images section
############################################################

build-images:
		@if [ -z "$(NO_CACHE)" ]; then \
			$(ISHIELD_REPO_ROOT)/build/build_images.sh false; \
		else \
			$(ISHIELD_REPO_ROOT)/build/build_images.sh $(NO_CACHE); \
		fi


push-images:
		${ISHIELD_REPO_ROOT}/build/push_images.sh

pull-images:
		${ISHIELD_REPO_ROOT}/build/pull_images.sh

############################################################
# cli section
############################################################

build-cli:
	cd ${CLI_DIR} && go mod tidy && go build -o build/ishieldctl main.go

############################################################
# bundle section
############################################################

build-bundle:
		$(ISHIELD_REPO_ROOT)/build/build_bundle.sh

############################################################
# clean section
############################################################
clean::

############################################################
# check copyright section
############################################################
copyright-check:
	 - $(ISHIELD_REPO_ROOT)/build/copyright-check.sh $(TRAVIS_BRANCH)

############################################################
# unit test section
############################################################

test-prereq:
	source ${ENVTEST_ASSETS_DIR}/setup-envtest.sh && fetch_envtest_tools ${ENVTEST_ASSETS_DIR} && setup_envtest_env ${ENVTEST_ASSETS_DIR}

test-unit: test-prereq test-init test-verify test-init-op test-verify-op 
test-init:
	cd $(SHIELD_DIR) &&  go test -v  $(shell cd $(SHIELD_DIR) && go list ./... | grep -v /vendor/ ) | tee $(TMP_DIR)results.txt

test-init-op:
	cd $(SHIELD_OP_DIR) &&  go test -v  $(shell cd $(SHIELD_OP_DIR) && go list ./... | grep -v /test ) | tee $(TMP_DIR)results_op.txt

test-verify:
	$(eval FAILURES=$(shell cat $(TMP_DIR)results.txt | grep "FAIL:"))
	# cat $(TMP_DIR)results.txt
	@$(if $(strip $(FAILURES)), echo "One or more unit tests failed. Failures: $(FAILURES)"; exit 1, echo "All unit tests passed successfully."; exit 0)

test-verify-op:
	$(eval FAILURES=$(shell cat $(TMP_DIR)results_op.txt | grep "FAIL:"))
	# cat $(TMP_DIR)results_op.txt
	@$(if $(strip $(FAILURES)), echo "One or more unit tests failed. Failures: $(FAILURES)"; exit 1, echo "All unit tests passed successfully."; exit 0)

############################################################
# e2e test section
############################################################

.PHONY: test-e2e test-e2e-kind test-e2e-remote test-e2e-common test-e2e-clean-common
.PHONY: check-kubeconfig create-kind-cluster setup-image pull-images push-images-to-local delete-kind-cluster
.PHONY: install-crds setup-ishield-env install-operator setup-tmp-cr setup-test-env e2e-test delete-test-env delete-keyring-secret delete-operator clean-tmp delete-operator
.PHONY: create-ns create-keyring-secret tag-images-to-local
.PHONY: test-gpg-annotation


.EXPORT_ALL_VARIABLES:
TMP_CR_FILE=$(TMP_DIR)apis_v1_integrityshield.yaml
TMP_CR_AC_FILE=$(TMP_DIR)apis_v1_integrityshield_ac.yaml

ifeq ($(ISHIELD_TEST_ENV), remote)
TMP_OBSERVER_IMG=$(REGISTRY)/$(ISHIELD_OBSERVER)
TMP_ADMISSION_CONTROLLER_IMG=$(REGISTRY)/$(ISHIELD_ADMISSION_CONTROLLER)
TMP_ISHIELD_IMG=$(REGISTRY)/$(ISHIELD_IMAGE)
OPERATOR_IMG=$(ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION)
else
TMP_OBSERVER_IMG=$(LOCAL_REGISTRY)/$(ISHIELD_OBSERVER)
TMP_ADMISSION_CONTROLLER_IMG=$(LOCAL_REGISTRY)/$(ISHIELD_ADMISSION_CONTROLLER)
TMP_ISHIELD_IMG=$(LOCAL_REGISTRY)/$(ISHIELD_IMAGE)
OPERATOR_IMG=$(TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION)
endif

# export KUBE_CONTEXT_USERNAME=kind-test-managed

test-e2e: export KUBECONFIG=$(SHIELD_OP_DIR)kubeconfig_managed
# perform test in a kind cluster after creating the cluster
test-e2e: create-kind-cluster setup-test-env setup-image test-e2e-common delete-test-env test-e2e-clean-common delete-kind-cluster

# perform test in an existing kind cluster and do not clean
test-e2e-kind: setup-test-env setup-image test-e2e-common

# perform test in an existing cluster (e.g. ROKS, OCP etc.)
test-e2e-remote: setup-test-env-remote build-images push-images test-e2e-common delete-test-env-remote test-e2e-clean-common

# common steps to do e2e test in an existing cluster
test-e2e-common: check-kubeconfig install-crds install-operator setup-tmp-cr e2e-test

# common steps to clean e2e test resources in an existing cluster
test-e2e-clean-common: delete-operator clean-tmp

check-kubeconfig:
	@if [ -z "$(KUBECONFIG)" ]; then \
		echo KUBECONFIG is empty.; \
		exit 1;\
	fi

create-kind-cluster:
	@echo "creating cluster"
	# kind create cluster --name test-managed
	bash $(SHIELD_OP_DIR)test/create-kind-cluster.sh
	kind get kubeconfig --name test-managed > $(SHIELD_OP_DIR)kubeconfig_managed

delete-kind-cluster:
	@echo deleting cluster
	kind delete cluster --name test-managed

setup-image: build-images push-images-to-local

tag-images-to-local:
	@echo tag image for local registry
	docker tag $(ISHIELD_API_IMAGE_NAME_AND_VERSION) $(TEST_ISHIELD_API_IMAGE_NAME_AND_VERSION)
	docker tag $(ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION) $(TEST_ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION)
	docker tag $(ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION) $(TEST_ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION)
	docker tag $(ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION) $(TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION)

push-images-to-local: tag-images-to-local
	@echo push image into local registry
	docker push $(TEST_ISHIELD_API_IMAGE_NAME_AND_VERSION)
	docker push $(TEST_ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION)
	docker push $(TEST_ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION)
	docker push $(TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION)

setup-test-env: create-ns create-keyring-secret
	@echo
	@echo creating test namespace
	kubectl create ns $(TEST_NS)
	@echo deploying gatekeeper
	kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.5/deploy/gatekeeper.yaml
	
setup-test-env-remote: create-ns create-keyring-secret
	@echo
	@echo creating test namespace
	kubectl create ns $(TEST_NS)

delete-test-env: delete-keyring-secret
	@echo
	@echo deleting test namespace
	# $TEST_NS will be deleted in e2e test usually, so ignore not found error.
	kubectl delete ns $(TEST_NS) --ignore-not-found=true
	@echo deleting gatekeeper
	kubectl delete -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.5/deploy/gatekeeper.yaml

delete-test-env-remote: delete-keyring-secret
	@echo
	@echo deleting test namespace
	# $TEST_NS will be deleted in e2e test usually, so ignore not found error.
	kubectl delete ns $(TEST_NS) --ignore-not-found=true

create-keyring-secret:
	@echo creating keyring-secret
	# kubectl create -f $(SHIELD_OP_DIR)test/deploy/certpool_secret.yaml -n $(ISHIELD_NS)
	kubectl create -f $(SHIELD_OP_DIR)test/deploy/pgp-keyring-secret.yaml -n $(ISHIELD_NS)

delete-keyring-secret:
	@echo
	@echo deleting keyring-secret
	kubectl delete -f $(SHIELD_OP_DIR)test/deploy/pgp-keyring-secret.yaml -n $(ISHIELD_NS)

e2e-test:
	@echo
	@echo run test
	$(ISHIELD_REPO_ROOT)/build/check_test_results.sh

.EXPORT_ALL_VARIABLES:
TEST_SIGNER_SUBJECT_EMAIL=signer@enterprise.com

test-gpg-annotation:
	@echo
	$(ISHIELD_REPO_ROOT)/build/run_unit_test_sign_script.sh $(TEST_SIGNER_SUBJECT_EMAIL) $(TMP_DIR)

############################################################
# setup ishield
############################################################

install-ishield: check-kubeconfig install-crds install-operator create-cr 

uninstall-ishield: delete-cr delete-operator

create-ns:
	@echo
	@echo creating namespace
	kubectl create ns $(ISHIELD_NS)

install-crds:
	@echo installing crds
	kustomize build $(SHIELD_OP_DIR)config/crd | kubectl apply -f -

delete-crds:
	@echo deleting crds
	kustomize build $(SHIELD_OP_DIR)config/crd | kubectl delete -f -

install-operator:
	@echo
	@echo setting image
	cp $(SHIELD_OP_DIR)config/manager/kustomization.yaml $(TMP_DIR)kustomization.yaml  #copy original file to tmp dir.
	cd $(SHIELD_OP_DIR)config/manager && kustomize edit set image controller=$(OPERATOR_IMG)
	@echo installing operator
	kustomize build $(SHIELD_OP_DIR)config/default | kubectl apply --validate=false -f -
	cp $(TMP_DIR)kustomization.yaml $(SHIELD_OP_DIR)config/manager/kustomization.yaml  #put back the original file from tmp dir.

delete-operator:
	@echo
	@echo deleting operator
	kustomize build $(SHIELD_OP_DIR)config/default | kubectl delete -f -

create-cr:
	kubectl apply -f ${SHIELD_OP_DIR}config/samples/apis_v1_integrityshield.yaml -n $(ISHIELD_NS)

delete-cr:
	kubectl delete -f ${SHIELD_OP_DIR}config/samples/apis_v1_integrityshield.yaml -n $(ISHIELD_NS)

deploy-cr-ac:
	kubectl apply -f $(SHIELD_OP_DIR)config/samples/apis_v1_integrityshield_ac.yaml -n $(ISHIELD_NS)

delete-cr-ac:
	kubectl delete -f $(SHIELD_OP_DIR)config/samples/apis_v1_integrityshield_ac.yaml -n $(ISHIELD_NS)

# create a temporary cr with update image names as well as signers
setup-tmp-cr:
	@echo
	@echo prepare cr
	@echo copy cr into tmp dir
	cp $(SHIELD_OP_DIR)config/samples/apis_v1_integrityshield_local.yaml $(TMP_CR_FILE)
	cp $(SHIELD_OP_DIR)config/samples/apis_v1_integrityshield_ac.yaml $(TMP_CR_AC_FILE)
	@echo insert image
	YQ_VERSION=$$(yq --version 2>&1 | awk '{print $$3}' | cut -c 1 ); \
	if [[ $$YQ_VERSION == "3" ]]; then \
		yq write -i $(TMP_CR_FILE) spec.shieldApi.image $(TMP_ISHIELD_IMG) ; \
		yq write -i $(TMP_CR_FILE) spec.shieldApi.imagePullPolicy Always ; \
		yq write -i $(TMP_CR_FILE) spec.shieldApi.resources.limits.cpu 200m ; \
		yq write -i $(TMP_CR_FILE) spec.shieldApi.resources.limits.memory 256Mi ; \
		yq write -i $(TMP_CR_FILE) spec.observer.image $(TMP_OBSERVER_IMG) ; \
		yq write -i $(TMP_CR_FILE) spec.observer.imagePullPolicy Always ; \
		yq write -i $(TMP_CR_FILE) spec.observer.resources.limits.cpu 200m ; \
		yq write -i $(TMP_CR_FILE) spec.observer.resources.limits.memory 256Mi ; \
		yq write -i $(TMP_CR_AC_FILE) spec.admissionController.image $(TMP_ADMISSION_CONTROLLER_IMG) ; \
		yq write -i $(TMP_CR_AC_FILE) spec.admissionController.imagePullPolicy Always ; \
		yq write -i $(TMP_CR_AC_FILE) spec.admissionController.resources.limits.cpu 200m ; \
		yq write -i $(TMP_CR_AC_FILE) spec.admissionController.resources.limits.memory 256Mi ; \
		yq write -i $(TMP_CR_AC_FILE) spec.observer.image $(TMP_OBSERVER_IMG) ; \
		yq write -i $(TMP_CR_AC_FILE) spec.observer.imagePullPolicy Always ; \
		yq write -i $(TMP_CR_AC_FILE) spec.observer.resources.limits.cpu 200m ; \
		yq write -i $(TMP_CR_AC_FILE) spec.observer.resources.limits.memory 256Mi ; \
	elif [[ $$YQ_VERSION == "4" ]]; then \
		yq eval -i $(TMP_CR_FILE) ".spec.shieldApi.image = $(TMP_ISHIELD_IMG)" ; \
		yq eval -i $(TMP_CR_FILE) ".spec.shieldApi.imagePullPolicy = Always" ; \
		yq eval -i $(TMP_CR_FILE) ".spec.shieldApi.resources.limits.cpu = 200m" ; \
		yq eval -i $(TMP_CR_FILE) ".spec.shieldApi.resources.limits.memory = 256Mi" ; \
		yq eval -i $(TMP_CR_FILE) ".spec.observer.image = $(TMP_OBSERVER_IMG)" ; \
		yq eval -i $(TMP_CR_FILE) ".spec.observer.imagePullPolicy = Always" ; \
		yq eval -i $(TMP_CR_FILE) ".spec.observer.resources.limits.cpu = 200m" ; \
		yq eval -i $(TMP_CR_FILE) ".spec.observer.resources.limits.memory = 256Mi" ; \
		yq eval -i $(TMP_CR_AC_FILE) ".spec.admissionController.image = $(TMP_ADMISSION_CONTROLLER_IMG)" ; \
		yq eval -i $(TMP_CR_AC_FILE) ".spec.admissionController.imagePullPolicy = Always" ; \
		yq eval -i $(TMP_CR_AC_FILE) ".spec.admissionController.resources.limits.cpu = 200m" ; \
		yq eval -i $(TMP_CR_AC_FILE) ".spec.admissionController.resources.limits.memory = 256Mi" ; \
		yq eval -i $(TMP_CR_AC_FILE) ".spec.observer.image = $(TMP_OBSERVER_IMG)" ; \
		yq eval -i $(TMP_CR_AC_FILE) ".spec.observer.imagePullPolicy = Always" ; \
		yq eval -i $(TMP_CR_AC_FILE) ".spec.observer.resources.limits.cpu = 200m" ; \
		yq eval -i $(TMP_CR_AC_FILE) ".spec.observer.resources.limits.memory = 256Mi" ; \
	fi

create-tmp-cr:
	kubectl apply -f $(TMP_CR_FILE) -n $(ISHIELD_NS)

delete-tmp-cr:
	kubectl delete -f $(TMP_CR_FILE) -n $(ISHIELD_NS)

# show log
log-api:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_api.sh
log-operator:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_operator.sh
log-observer:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_observer.sh
log-ac-server:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_ac.sh

clean-tmp:
	@if [ -f "$(TMP_CR_FILE)" ]; then\
		rm $(TMP_CR_FILE);\
	fi
	@if [ -f "$(TMP_CR_AC_FILE)" ]; then\
		rm $(TMP_CR_AC_FILE);\
	fi

.PHONY: sec-scan

sec-scan:
	$(ISHIELD_REPO_ROOT)/build/sec_scan.sh

.PHONY: sonar-go-test-ishield sonar-go-test-op

sonar-go-test-ishield:
	@if [ "$(ISHIELD_ENV)" = remote ]; then \
		make go/gosec-install; \
	fi
	@echo "-> Starting sonar-go-test"
	@echo "--> Starting go test"
	cd $(SHIELD_DIR) && go test -coverprofile=coverage.out -json ./... | tee report.json | grep -v '"Action":"output"'
	@echo "--> Running gosec"
	gosec -fmt sonarqube -out gosec.json -no-fail ./...
	@echo "---> gosec gosec.json"
	@cat gosec.json
	@if [ "$(ISHIELD_ENV)" = remote ]; then \
		echo "--> Running sonar-scanner"; \
		sonar-scanner --debug || echo "Sonar scanner is not available"; \
	fi

sonar-go-test-op:
	@if [ "$(ISHIELD_ENV)" = remote ]; then \
		make go/gosec-install; \
	fi
	@echo "-> Starting sonar-go-test"
	@echo "--> Starting go test"
	cd $(SHIELD_OP_DIR) && go test -coverprofile=coverage.out -json  $(shell cd $(SHIELD_OP_DIR) && go list ./... | grep -v /test/) | tee report.json | grep -v '"Action":"output"'
	@echo "--> Running gosec"
	gosec -fmt sonarqube -out gosec.json -no-fail ./...
	@echo "---> gosec gosec.json"
	@cat gosec.json
	@if [ "$(ISHIELD_ENV)" = remote ]; then \
		echo "--> Running sonar-scanner"; \
		sonar-scanner --debug || echo "Sonar scanner is not available"; \
	fi

.PHONY: publish

publish:
	$(ISHIELD_REPO_ROOT)/build/publish_images.sh
	$(ISHIELD_REPO_ROOT)/build/publish_bundle_ocm.sh

setup-demo:
	@echo
	@echo setting image
	cp $(SHIELD_OP_DIR)config/manager/kustomization.yaml $(TMP_DIR)kustomization.yaml  #copy original file to tmp dir.
	cd $(SHIELD_OP_DIR)config/manager && kustomize edit set image controller=$(DEMO_ISHIELD_OP_IMAGE_NAME)
	@echo installing operator
	kustomize build $(SHIELD_OP_DIR)config/default | kubectl apply --validate=false -f -
	cp $(TMP_DIR)kustomization.yaml $(SHIELD_OP_DIR)config/manager/kustomization.yaml
	@echo prepare cr
	@echo copy cr into tmp dir
	cp $(SHIELD_OP_DIR)config/samples/apis_v1_integrityshield.yaml $(TMP_CR_FILE)
	@echo insert image
	yq write -i $(TMP_CR_FILE) spec.observer.image $(DEMO_ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME)
	yq write -i $(TMP_CR_FILE) spec.observer.imagePullPolicy Always
	yq write -i $(TMP_CR_FILE) spec.shieldApi.image $(DEMO_ISHIELD_API_IMAGE_NAME)
	yq write -i $(TMP_CR_FILE) spec.shieldApi.imagePullPolicy Always
	kubectl apply -f $(TMP_CR_FILE) -n $(ISHIELD_NS)

.PHONY: create-private-registry

create-private-registry:
	$(ISHIELD_REPO_ROOT)/build/create-private-registry.sh

delete-private-registry:
	$(ISHIELD_REPO_ROOT)/build/delete-private-registry.sh

.PHONY: update-version

# use this command to update VERSION  after doing 'make build-bundle'
update-version:
	$(ISHIELD_REPO_ROOT)/build/update-version.sh

# Before executing this target,  change BUNDLE_REGISTRY

test-e2e-bundle:
	make clean-e2e-test-log
	make setup-olm-local
	make setup-image # execute `make setup-image` for making sure new images exist
	make build-bundle # Used for ISHIELD_ENV=local/remote
	make deploy-bundle-local
	make check-bundle-local
	make bundle-test-local

deploy-bundle-local:
	$(ISHIELD_REPO_ROOT)/build/deploy-bundle-local.sh

check-bundle-local:
	$(ISHIELD_REPO_ROOT)/build/check-bundle-deployment-local.sh

test-e2e-bundle-clean-local:
	make test-e2e-clean-common --ignore-errors
	make clean-e2e-bundle-test-local
	make clean-e2e-test-log

clean-e2e-bundle-test-local:
	$(ISHIELD_REPO_ROOT)/build/clean-e2e-bundle-test-local.sh

clean-e2e-test-log:
	$(ISHIELD_REPO_ROOT)/build/clean-e2e-test-log.sh

setup-olm-local:
	$(ISHIELD_REPO_ROOT)/build/setup-olm-local.sh

bundle-test-local:
	make create-keyring-secret
	make setup-tmp-cr
	make setup-test-env
	make e2e-test
