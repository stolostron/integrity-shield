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

echo "SECURITY SCAN GOES HERE!"

# Run our build target

echo "Init"
make init

echo "Scaning integrity shield images : $(date)"

echo ISHIELD_VERSION ${ISHIELD_VERSION}
export SECURITYSCANS_IMAGE_NAME=${ISHIELD_IMAGE}
echo SECURITYSCANS_IMAGE_NAME ${SECURITYSCANS_IMAGE_NAME}
make security/scans

export SECURITYSCANS_IMAGE_NAME=${ISHIELD_OBSERVER}
echo SECURITYSCANS_IMAGE_NAME ${SECURITYSCANS_IMAGE_NAME}
make security/scans

# export SECURITYSCANS_IMAGE_NAME=${ISHIELD_REPORTER}
# echo SECURITYSCANS_IMAGE_NAME ${SECURITYSCANS_IMAGE_NAME}
# make security/scans

export SECURITYSCANS_IMAGE_NAME=${ISHIELD_ADMISSION_CONTROLLER}
echo SECURITYSCANS_IMAGE_NAME ${SECURITYSCANS_IMAGE_NAME}
make security/scans

export SECURITYSCANS_IMAGE_NAME=${ISHIELD_OPERATOR}
echo SECURITYSCANS_IMAGE_NAME ${SECURITYSCANS_IMAGE_NAME}
make security/scans

echo "Scanning integrity shield images completed : $(date)"
