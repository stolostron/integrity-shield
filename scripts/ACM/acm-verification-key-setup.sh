#
# Copyright 2021 IBM Corporation
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
#!/bin/bash

set -e
set -o pipefail


CMDNAME=`basename $0`

# Display help information
help () {
  echo "Deploy verification key secret to hub and target clusters by RHACM Subscription"
  echo ""
  echo "Prerequisites:"
  echo " - kubectl CLI must be pointing to the cluster to which to deploy verification key"
  echo ""
  echo "Usage:"
  echo "  $CMDNAME [-l <key=value>] [-p <path/to/file>] [-n <namespace>] [-s <name>]"
  echo ""
  echo "  -h|--help                   Display this menu"
  echo "  -l|--label <key=value>      Label for target clusters"
  echo '                                (Default label: "environment=dev")'
  echo "  -p|--path <path/to/file>    Path to the public key file"
  echo "                                (Default path: /tmp/public.gpg)"
  echo "  -s|--secret <name>          Secert name of the deployed public key"
  echo '                                (Default name: "keyring-secret")'
  echo "  -n|--namespace <namespace>  Namespace on the cluster to deploy the key secret"
  echo '                                (Default namespace: "integrity-shield-operator-system")'
  echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            -h|--help)
            help
            exit 0
            ;;
            -l|--label)
            shift
            TARGET_LABEL=${1}
            shift
            ;;
            -s|--secret)
            shift
            KEY_SECRET_NAME=${1}
            shift
            ;;
            -p|--path)
            shift
            KEY_FILE_PATH=${1}
            shift
            ;;
            -n|--namespace)
            shift
            NAMESPACE=${1}
            shift
            ;;
            *)    # default
            echo "Invalid input: ${1}"
            exit 1
            shift
            ;;
        esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [[ -z $TARGET_LABEL ]]; then
  TARGET_LABEL=environment=dev
fi

if [[ -z $KEY_SECRET_NAME ]]; then
  KEY_SECRET_NAME=keyring-secret
fi

if [[ -z $KEY_FILE_PATH ]]; then
  KEY_FILE_PATH=/tmp/pubring.gpg
fi

if [[ -z $NAMESPACE ]]; then
  NAMESPACE=integrity-shield-operator-system
fi


if ! [ -f "$KEY_FILE_PATH" ]; then
    echo 'Error: The verification key file `'$KEY_FILE_PATH'` is not found.' >&2
    exit 1
fi

if ! [ -x "$(command -v kubectl)" ]; then
    echo 'Error: kubectl is not installed.' >&2
    exit 1
fi

PUBRING_KEY_NAME=$KEY_SECRET_NAME
PUBRING_KEY_FILE_PATH=$KEY_FILE_PATH
PLACEMENT_KEY_VALUE=$TARGET_LABEL

if [ -z "$PLACEMENT_KEY_VALUE" ]; then
    echo "Please pass placement rule label as parameter e.g. '--label environment=dev'"
    exit 1
else
    PLACEMENT_KEY=$(echo ${PLACEMENT_KEY_VALUE} | cut -d'=' -f1)
    PLACEMENT_VALUE=$(echo ${PLACEMENT_KEY_VALUE} | cut -d'=' -f2)
fi


if [ -z "$PLACEMENT_KEY" ]; then
    echo "Please pass placement rule label as parameter e.g. '--label environment=dev'"
    exit 1
fi


if [ -z "$PLACEMENT_VALUE" ]; then
    echo "Please pass placement rule label as parameter e.g. '--label environment=dev'"
    exit 1
fi


if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    BASE='base64 -w 0'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    BASE='base64'
fi


cat <<EOF
apiVersion: v1
data:
  key: `cat ${PUBRING_KEY_FILE_PATH} | ${BASE}`
kind: Secret
metadata:
  annotations:
    apps.open-cluster-management.io/deployables: "true"
  name: ${PUBRING_KEY_NAME}
  namespace: ${NAMESPACE}
type: Opaque
---
apiVersion: apps.open-cluster-management.io/v1
kind: Channel
metadata:
  name: ${PUBRING_KEY_NAME}-deployments
  namespace: ${NAMESPACE}
spec:
  pathname: ${NAMESPACE}
  sourceNamespaces:
  - ${NAMESPACE}
  type: Namespace
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
  name: secret-placement
  namespace: ${NAMESPACE}
spec:
  clusterConditions:
  - status: "True"
    type: ManagedClusterConditionAvailable
  clusterSelector:
    matchExpressions:
    - key: ${PLACEMENT_KEY}
      operator: In
      values:
      - ${PLACEMENT_VALUE}
---
apiVersion: apps.open-cluster-management.io/v1
kind: Subscription
metadata:
  name: ${PUBRING_KEY_NAME}
  namespace: ${NAMESPACE}
spec:
  channel: ${NAMESPACE}/${PUBRING_KEY_NAME}-deployments
  placement:
    placementRef:
      kind: PlacementRule
      name: secret-placement
EOF
