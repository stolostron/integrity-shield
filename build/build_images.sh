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

CMDNAME=`basename $0`
if [ $# -ne 1 ]; then
  echo "Usage: $CMDNAME <no-cache>" 1>&2
  exit 1
fi

NO_CACHE=$1

if ! [ -x "$(command -v docker)" ]; then
    echo 'Error: docker is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v go)" ]; then
    echo 'Error: go is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v operator-sdk)" ]; then
    echo 'Error: operator-sdk is not installed.' >&2
    exit 1
fi

if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set root directory for IShield repository"
    exit 1
fi

if [ -z "$ISHIELD_API_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_API_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_REPORTER_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_REPORTER_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_OPERATOR" ]; then
    echo "ISHIELD_OPERATOR is empty. Please set IShield build env settings."
    exit 1
fi


# Build ishield-api image
echo -----------------------------
echo [1/5] Building ishield-api image.
cd ${SHIELD_DIR}
go mod tidy
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/ishield-api ./
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi

if [ "$NO_CACHE" = true ] ; then
     docker build -t ${ISHIELD_API_IMAGE_NAME_AND_VERSION} . --no-cache
else
    docker build -t ${ISHIELD_API_IMAGE_NAME_AND_VERSION} .
fi

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

# Build ishield-ac-server image
echo -----------------------------
echo [2/5] Building ishield-ac-server image.
cd ${SHIELD_AC_DIR}
go mod tidy
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -o build/_bin/k8s-manifest-sigstore ./
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
if [ "$NO_CACHE" = true ] ; then
     docker build -t ${ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION} . --no-cache
else
     docker build -t ${ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION} . 
fi

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

# Build ishield-observer image
echo -----------------------------
echo [3/5] Building ishield-observer image.
cd ${SHIELD_OBSERVER_DIR}
go mod tidy
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/ishield-observer ./
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
if [ "$NO_CACHE" = true ] ; then
    docker build -t ${ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION} . --no-cache
else
    docker build -t ${ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION} .
fi

# Build ishield-reporter image
echo -----------------------------
echo [4/5] Building ishield-reporter image.
cd ${SHIELD_REPORTER_DIR}
go mod tidy
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/ishield-reporter ./
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
if [ "$NO_CACHE" = true ] ; then
    docker build -t ${ISHIELD_REPORTER_IMAGE_NAME_AND_VERSION} . --no-cache
else
    docker build -t ${ISHIELD_REPORTER_IMAGE_NAME_AND_VERSION} .
fi

# Build integrity-shield-operator image
echo -----------------------------
echo [5/5] Building integrity-shield-operator image.
cd ${SHIELD_OP_DIR}
go mod tidy
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_output/bin/integrity-shield-operator main.go
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
if [ "$NO_CACHE" = true ] ; then
    docker build . -t ${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION} --no-cache
else
    docker build . -t ${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}
fi

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi

echo done.
echo -----------------------------
echo ""

echo Completed.
