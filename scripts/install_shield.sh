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

if ! [ -x "$(command -v kubectl)" ]; then
    echo 'Error: kubectl is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v kustomize)" ]; then
    echo 'Error: kustomize is not installed.' >&2
    exit 1
fi

if [ -z "$ISHIELD_NS" ]; then
    echo "ISHIELD_NS is empty. Please set namespace name for integrity-shield."
    exit 1
fi

if [ -z "$ISHIELD_ENV" ]; then
    echo "ISHIELD_ENV is empty. Please set local or remote."
    exit 1
fi

if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set root directory for IShield repository"
    exit 1
fi

IMG=quay.io/open-cluster-management/integrity-shield-operator:0.3.0
SHIELD_OP_DIR=${ISHIELD_REPO_ROOT}"/integrity-shield-operator/"

echo ""
echo "------------- Set integrity-shield operator watch namespace -------------"
echo ""
export WATCH_NAMESPACE=$ISHIELD_NS

echo ""
echo "------------- Install integrity-shield -------------"
echo ""

echo ""
echo "------------- Create crd -------------"
echo ""
cd ${SHIELD_OP_DIR}
kustomize build ${SHIELD_OP_DIR}config/crd | kubectl apply -f -

echo ""
echo "------------- Install operator -------------"
echo ""

cd ${SHIELD_OP_DIR}config/manager
kustomize edit set image controller=${IMG}
kustomize build ${SHIELD_OP_DIR}config/default | kubectl apply -f -

echo ""
echo "------------- Create CR -------------"
echo ""
cd $ISHIELD_REPO_ROOT

if [ $ISHIELD_ENV = "local" ]; then
   kubectl apply -f ${SHIELD_OP_DIR}config/samples/apis_v1alpha1_integrityshield_local.yaml -n $ISHIELD_NS
else
   kubectl apply -f ${SHIELD_OP_DIR}config/samples/apis_v1alpha1_integrityshield.yaml -n $ISHIELD_NS
fi
