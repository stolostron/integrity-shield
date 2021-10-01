#!/bin/bash
#
# Copyright 2020 IBM Corporation.
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

set -e

echo "INSTALL DEPENDENCIES GOES HERE!"

OS_NAME=$(uname -s)

OPERATOR_SDK_VERSION=v1.1.0

if ! [ -x "$(command -v operator-sdk)" ]; then
	echo "installing operator-sdk"
	if [[ "$OS_NAME" == "Linux" ]]; then
		curl -L https://github.com/operator-framework/operator-sdk/releases/download/$OPERATOR_SDK_VERSION/operator-sdk-$OPERATOR_SDK_VERSION-x86_64-linux-gnu -o operator-sdk
	elif [[ "$OS_NAME" == "Darwin" ]]; then
		curl -L https://github.com/operator-framework/operator-sdk/releases/download/$OPERATOR_SDK_VERSION/operator-sdk-$OPERATOR_SDK_VERSION-x86_64-apple-darwin -o operator-sdk
	fi
	chmod +x operator-sdk
	sudo mv operator-sdk /usr/local/bin/operator-sdk
	operator-sdk version
	echo "done"
fi

OPM_VERSION=v1.15.1

if ! [ -x "$(command -v opm)" ]; then
	echo "installing opm"
	if [[ "$OS_NAME" == "Linux" ]]; then
	    OPM_URL=https://github.com/operator-framework/operator-registry/releases/download/$OPM_VERSION/linux-amd64-opm
	elif [[ "$OS_NAME" == "Darwin" ]]; then
	    OPM_URL=https://github.com/operator-framework/operator-registry/releases/download/$OPM_VERSION/darwin-amd64-opm
	fi

	echo $GOPATH
	sudo wget -nv $OPM_URL -O /usr/local/bin/opm
	sudo chmod +x /usr/local/bin/opm
	/usr/local/bin/opm version
	echo "done"
fi

if ! [ -x "$(command -v kustomize)" ]; then
	echo "installing kustomize"
	if [[ "$OS_NAME" == "Linux" ]]; then
                where=$PWD
                if [ -f $where/kustomize ]; then
                  echo "A file named kustomize already exists (remove it first)."
                  exit 1
                fi

		wget https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v3.8.5/kustomize_v3.8.5_linux_amd64.tar.gz
                if [ -e ./kustomize_v*_linux_amd64.tar.gz ]; then
                   tar xzf ./kustomize_v*_linux_amd64.tar.gz
                else
                   echo "Error: kustomize binary with the version ${version#v} does not exist!"
                   exit 1
                fi
                ./kustomize version
                echo kustomize installed to current directory.
	elif [[ "$OS_NAME" == "Darwin" ]]; then
		curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash
	fi
	chmod +x ./kustomize
	sudo mv ./kustomize /usr/local/bin/kustomize
	echo "done"
fi


if ! [ -x "$(command -v yq)" ]; then
	echo "installing yq"
	sudo wget https://github.com/mikefarah/yq/releases/download/3.3.2/yq_linux_amd64 -O /usr/bin/yq
	sudo chmod +x /usr/bin/yq
	echo "done"
fi

if ! [ -x "$(command -v jq)" ]; then
	sudo apt -y install jq
fi

if ! [ -x "$(command -v kubectl)" ]; then
	echo "installing kubectl"
	if [[ "$OS_NAME" == "Linux" ]]; then
		curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
	elif [[ "$OS_NAME" == "Darwin" ]]; then
		curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/darwin/amd64/kubectl"
	fi
	chmod +x ./kubectl
	sudo mv ./kubectl /usr/local/bin/kubectl
	echo "done"
fi

if ! [ -x "$(command -v kind)" ]; then
	echo "installing kind"
	if [[ "$OS_NAME" == "Linux" ]]; then
		curl -k -Lo ./kind https://kind.sigs.k8s.io/dl/v0.9.0/kind-linux-amd64
	elif [[ "$OS_NAME" == "Darwin" ]]; then
		curl -k -Lo ./kind https://kind.sigs.k8s.io/dl/v0.9.0/kind-darwin-amd64
	fi

	chmod +x ./kind
	sudo mv ./kind /usr/local/bin/kind
	echo "done"
fi

# Install golangci-lint
if ! [ -x "$(command -v golangci-lint)" ]; then
	echo "installing golangci-lint"
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$(go env GOPATH)"/bin v1.32.0
	echo "done"
fi

echo "Finished setting up dependencies."
