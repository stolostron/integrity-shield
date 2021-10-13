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

if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set env."
    exit 1
fi

if [ -z "$SHIELD_OP_DIR" ]; then
    echo "SHIELD_OP_DIR is empty. Please set env."
    exit 1
fi

if [[ "$OS_NAME" == "Linux" ]]; then
    sed -i "s|$PREV_VERSION|$VERSION|" ${ISHIELD_REPO_ROOT}/docs/ACM/README_DISABLE_ISHIELD_PROTECTION_ACM_ENV.md
    sed -i "s|$PREV_VERSION|$VERSION|" ${ISHIELD_REPO_ROOT}/scripts/install_shield.sh
    sed -i "s|$PREV_VERSION|$VERSION|" ${ISHIELD_REPO_ROOT}/COMPONENT_VERSION
    sed -i "s|$PREV_VERSION|$VERSION|" ${SHIELD_OP_DIR}Makefile
    sed -i "s|$PREV_VERSION|$VERSION|" ${SHIELD_OP_DIR}config/manifests/bases/integrity-shield-operator.clusterserviceversion.yaml
elif [[ "$OS_NAME" == "Darwin" ]]; then
    sed -i '' "s|$PREV_VERSION|$VERSION|" ${ISHIELD_REPO_ROOT}/docs/ACM/README_DISABLE_ISHIELD_PROTECTION_ACM_ENV.md
    sed -i '' "s|$PREV_VERSION|$VERSION|" ${ISHIELD_REPO_ROOT}/scripts/install_shield.sh
    sed -i '' "s|$PREV_VERSION|$VERSION|" ${ISHIELD_REPO_ROOT}/COMPONENT_VERSION
    sed -i '' "s|$PREV_VERSION|$VERSION|" ${SHIELD_OP_DIR}Makefile
    sed -i '' "s|$PREV_VERSION|$VERSION|" ${SHIELD_OP_DIR}config/manifests/bases/integrity-shield-operator.clusterserviceversion.yaml
fi