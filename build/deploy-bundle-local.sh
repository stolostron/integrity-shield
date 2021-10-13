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

echo "CREATE BUNDLE RESOURCES GOES HERE!"


if [ -z "$SHIELD_OP_DIR" ]; then
    echo "SHIELD_OP_DIR is empty. Please set env."
    exit 1
fi

if [ -z "$ISHIELD_NS" ]; then
    echo "ISHIELD_NS is empty. Please set env."
    exit 1
fi

if [ -z "$TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION" ]; then
    echo "TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION is empty. Please set env."
    exit 1
fi


BUNDLE_INDX_IMAGE=${TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}
echo BUNDLE_INDX_IMAGE: ${BUNDLE_INDX_IMAGE}

STARTING_CSV=$(cat  $SHIELD_OP_DIR/bundle/manifests/integrity-shield-operator.clusterserviceversion.yaml | yq r - 'metadata.name')

if [ -z "$STARTING_CSV" ]; then
    echo "STARTING_CSV is empty. Please check if integrity-shield-operator.clusterserviceversion.yaml is generated correctly"
    exit 1
fi

echo ""
echo "-------------------------------------------------"
echo "Install bundle catalogsource"

cat <<EOF | kubectl create -f -
apiVersion: v1
kind: Namespace
metadata:
  name: ${ISHIELD_NS}
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: operatorgroup
  namespace: ${ISHIELD_NS}
spec:
  targetNamespaces:
  - ${ISHIELD_NS}
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: integrity-shield-operator
  namespace: ${ISHIELD_NS}
spec:
  channel: ${CHANNELS}
  installPlanApproval: Automatic
  name: integrity-shield-operator
  source: integrity-shield-operator-catalog
  sourceNamespace: olm
  startingCSV: ${STARTING_CSV}
---
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: integrity-shield-operator-catalog
  namespace: olm
spec:
  displayName: Integrity Ishield Operator
  image: ${BUNDLE_INDX_IMAGE}
  publisher: Community
  sourceType: grpc
  updateStrategy:
    registryPoll:
      interval: 15m
EOF
