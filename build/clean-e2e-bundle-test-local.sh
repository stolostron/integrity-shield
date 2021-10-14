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

echo "E2E TEST BUNDLE CLEAN GOES HERE!"

if [ -z "$ISHIELD_NS" ]; then
    echo "ISHIELD_NS is empty. Please set env."
    exit 1
fi

if [ -z "$OLM_VERSION" ]; then
    echo "OLM_VERSION is empty. Please set olm version."
    exit 1
fi

if [ -z "$ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION is empty. Please set env."
    exit 1
fi

if [ "${ISHIELD_ENV}" = local ]; then
   BUNDLE_INDEX_IMAGE=${ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}
else
   BUNDLE_INDEX_IMAGE=${ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
fi
echo "Testing BUNDLE_INDEX_IMAGE: $BUNDLE_INDEX_IMAGE"
echo ""
echo "-------------------------------------------------"

NS_EXIST=$(kubectl get ns | grep ${ISHIELD_NS} | cut -d' ' -f1)


if [ ! -z $NS_EXIST ]; then
cat <<EOF | kubectl delete -f -
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
  channel: ${ISHIELD_DEFAULT_CHANNEL}
  name: integrity-shield-operator
  source: integrity-shield-operator-catalog
  sourceNamespace: olm
---
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: integrity-shield-operator-catalog
  namespace: olm
spec:
  displayName: Integrity Shield Operator
  image: ${BUNDLE_INDEX_IMAGE}
  publisher: Community
  sourceType: grpc
  updateStrategy:
    registryPoll:
      interval: 45m
EOF

fi

echo "Delete OLM install"
echo "-------------------------------------------------"

OLM_NS_EXIST=$(kubectl get ns | grep olm | cut -d' ' -f1)

if [ ! -z  $OLM_NS_EXIST ]; then
     url=https://raw.githubusercontent.com/operator-framework/operator-lifecycle-manager/${OLM_VERSION}/deploy/upstream/quickstart/
     olm_url="${url}olm.yaml"
     crd_url="${url}crds.yaml"
     curl -s -k $olm_url | yq r -d"*" - -j | while read doc;
     do
        kind=$(echo $doc | yq r - -j | jq -r '.kind')
        name=$(echo $doc | yq r - -j | jq -r '.metadata.name')
        ns=$(echo $doc | yq r - -j | jq -r '.metadata.namespace')
        if [ ! $kind = 'Namespace' ]; then
           if [ -z $ns ]; then
             echo "Deleting $kind $name in $ns"
             kubectl delete $kind $name
           else
             echo "Deleting $kind $name in $ns"
             kubectl delete $kind $name -n $ns
           fi
        fi
     done

     kubectl delete -f "${crd_url}"
     kubectl delete apiservices.apiregistration.k8s.io v1.packages.operators.coreos.com
     kubectl delete ns olm
     kubectl delete ns operators
fi
