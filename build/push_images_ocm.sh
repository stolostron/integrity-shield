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

echo "IMAGE PUSH GOES HERE!"

# Tag images with COMPONENT_TAG_EXTENSION
docker tag ${ISHIELD_API_IMAGE_NAME_AND_VERSION} ${ISHIELD_API_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
docker tag ${ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION} ${ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
# docker tag ${ISHIELD_REPORTER_IMAGE_NAME_AND_VERSION} ${ISHIELD_REPORTER_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
docker tag ${ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION} ${ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
docker tag ${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION} ${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}

export COMPONENT_VERSION=${ISHIELD_VERSION}
export COMPONENT_DOCKER_REPO=${REGISTRY}

# Push ${ISHIELD_IMAGE}
export COMPONENT_NAME=${ISHIELD_IMAGE}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
if [ `go env GOOS` == "linux" ]; then
    make component/push
fi

# Push ${ISHIELD_OBSERVER}
export COMPONENT_NAME=${ISHIELD_OBSERVER}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
if [ `go env GOOS` == "linux" ]; then
    make component/push
fi

# Push ${ISHIELD_REPORTER}
# export COMPONENT_NAME=${ISHIELD_REPORTER}
# export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
# if [ `go env GOOS` == "linux" ]; then
#     make component/push
# fi

# Push ${ISHIELD_ADMISSION_CONTROLLER}
export COMPONENT_NAME=${ISHIELD_ADMISSION_CONTROLLER}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
if [ `go env GOOS` == "linux" ]; then
    make component/push
fi


# Push ${ISHIELD_OPERATOR}
export COMPONENT_NAME=${ISHIELD_OPERATOR}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
if [ `go env GOOS` == "linux" ]; then
    make component/push
fi
