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


if ! [ -x "$(command -v docker)" ]; then
    echo 'Error: docker is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v opm)" ]; then
    echo 'Error: opm is not installed.' >&2
    exit 1
fi

if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set root directory for IShield repository"
    exit 1
fi

if [ -z "$SHIELD_OP_DIR" ]; then
    echo "SHIELD_OP_DIR is empty. Please set env."
    exit 1
fi


cd $SHIELD_OP_DIR

echo "Current directory: $(pwd)"

if [ "${ISHIELD_ENV}" = "remote" ]; then
   export COMPONENT_VERSION=${VERSION}
   export COMPONENT_DOCKER_REPO=${REGISTRY}
   TARGET_OPERATOR_IMG=${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
   TARGET_BUNDLE_IMG=${ISHIELD_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
   TARGET_INDEX_IMG_PREVIOUS_VERSION=${ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION}${COMPONENT_TAG_EXTENSION}
   TARGET_INDEX_IMG=${ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
elif [ "${ISHIELD_ENV}" = "local" ]; then
   TARGET_OPERATOR_IMG=${TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}
   TARGET_BUNDLE_IMG=${TEST_ISHIELD_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}
   TARGET_INDEX_IMG_PREVIOUS_VERSION=${TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION}
   TARGET_INDEX_IMG=${TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}
fi

# Build ishield-operator bundle
echo -----------------------------
echo [1/4] Building bundle
make bundle IMG=${TARGET_OPERATOR_IMG} VERSION=${VERSION}

# Temporary workarround for dealing with CRD generation issue
tmpcrd="${SHIELD_OP_DIR}/config/crd/bases/apis.integrityshield.io_integrityshieldren.yaml"
targetcrd="${SHIELD_OP_DIR}/config/crd/bases/apis.integrityshield.io_integrityshields.yaml"

if [ -f $tmpcrd ]; then
  sed -i 's/integrityshieldren/integrityshields/g' $tmpcrd
  mv $tmpcrd $targetcrd
fi

csvfile="bundle/manifests/integrity-shield-operator.clusterserviceversion.yaml"
cat $csvfile | yq r - -j >  tmp.json

change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "OwnNamespace").supported=true)') && echo "$change" >  tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "SingleNamespace").supported=true)') && echo "$change" > tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "MultiNamespace").supported=false)') && echo "$change" > tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "AllNamespaces").supported=false)') && echo "$change" > tmp.json

cat tmp.json  | yq r - -P > $csvfile
rm tmp.json

cp  ${ISHIELD_REPO_ROOT}/docs/README_OPERATOR_HUB.md ${TMP_DIR}README_OPERATOR_HUB.md

OS_NAME=$(uname -s)
if [[ "$OS_NAME" == "Darwin" ]]; then
   sedi=(-i "")
else
   sedi=(-i)
fi

sed "${sedi[@]}" '1,2d' ${ISHIELD_REPO_ROOT}/docs/README_OPERATOR_HUB.md

yq w -i $csvfile spec.description  -- "$(< ${ISHIELD_REPO_ROOT}/docs/README_OPERATOR_HUB.md)"
yq w -i $csvfile metadata.annotations.containerImage "${TARGET_OPERATOR_IMG}"

mv ${TMP_DIR}README_OPERATOR_HUB.md ${ISHIELD_REPO_ROOT}/docs/README_OPERATOR_HUB.md

docker pull ${TARGET_INDEX_IMG_PREVIOUS_VERSION} | grep "Image is up to date" && pull_status="pulled" || pull_status="failed"
if [ "$pull_status" = "failed" ]; then
  sed -i '/ replaces: /d' ${SHIELD_OP_DIR}/bundle/manifests/*.clusterserviceversion.yaml
fi

make bundle-build BUNDLE_IMG=${TARGET_BUNDLE_IMG}



# Push ishield-operator bundle
echo -----------------------------
echo [2/4] Pushing bundle

if [ "${ISHIELD_ENV}" = "remote" ]; then
    export COMPONENT_NAME=${ISHIELD_BUNDLE}
    export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
    docker login quay.io -u ${DOCKER_USER} -p ${DOCKER_PASS}
    make docker-push IMG=$DOCKER_IMAGE_AND_TAG
elif [ "${ISHIELD_ENV}" = "local" ]; then
    docker push ${TARGET_BUNDLE_IMG}
fi

# Prepare ishield-operator bundle index
echo -----------------------------
echo [3/4] Adding bundle to index

if [ "${ISHIELD_ENV}" = "remote" ]; then
    # use docker as an image build/pull tool
    if [ "$pull_status" = "failed" ]; then
        sudo /usr/local/bin/opm index add -c docker --generate --bundles ${TARGET_BUNDLE_IMG} \
                        --tag ${TARGET_INDEX_IMG} --out-dockerfile tmp.Dockerfile
    else
        echo "Succesfulling pulled previous index"
        sudo /usr/local/bin/opm index add -c docker --generate --bundles ${TARGET_BUNDLE_IMG} \
                        --from-index ${TARGET_INDEX_IMG_PREVIOUS_VERSION} \
                        --tag ${TARGET_INDEX_IMG} --out-dockerfile tmp.Dockerfile
    fi
elif [ "${ISHIELD_ENV}" = "local" ]; then
    # use containerd as an image build/pull tool
    if [ "$pull_status" = "failed" ]; then
        sudo /usr/local/bin/opm index add --generate --bundles ${TARGET_BUNDLE_IMG} \
                        --tag ${TARGET_INDEX_IMG} --out-dockerfile tmp.Dockerfile
    else
        echo "Succesfulling pulled previous index"
        sudo /usr/local/bin/opm index add --generate --bundles ${TARGET_BUNDLE_IMG} \
                        --from-index ${TARGET_INDEX_IMG_PREVIOUS_VERSION} \
                        --tag ${TARGET_INDEX_IMG} --out-dockerfile tmp.Dockerfile
    fi
fi



rm -f tmp.Dockerfile

# Build ishield-operator bundle index
echo -----------------------------
echo [3/4]  Building bundle index
docker build -f index.Dockerfile -t ${TARGET_INDEX_IMG} --build-arg USER_ID=1001 --build-arg GROUP_ID=12009  . --no-cache

# Push ishield-operator bundle index
echo -----------------------------
echo [3/4]  Pushing bundle index

if [ "${ISHIELD_ENV}" = "remote" ]; then
    export COMPONENT_NAME=${ISHIELD_INDEX}
    export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
    make docker-push IMG=$DOCKER_IMAGE_AND_TAG
elif [ "${ISHIELD_ENV}" = "local" ]; then
    docker push ${TARGET_INDEX_IMG}
fi
echo "Completed building bundle and index"

targetFile="${SHIELD_OP_DIR}bundle.Dockerfile"
licenseFile="${SHIELD_OP_DIR}license.txt"
$ISHIELD_REPO_ROOT/build/add_license.sh $targetFile $licenseFile
