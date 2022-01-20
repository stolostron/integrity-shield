#!/bin/bash
#
# Copyright 2022 IBM Corporation.
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

echo "SONAR GO TEST GOES HERE!"

. ${ISHIELD_REPO_ROOT}/ishield-build.conf

if [ "${ISHIELD_ENV}" = remote ]; then \
    make go/gosec-install; \
fi
echo "-> Starting sonar-go-test"
echo "--> Starting go test"
cd ${SHIELD_DIR} && go test -coverprofile=coverage.out -json ./... | tee report.json | grep -v '"Action":"output"'
echo "--> Running gosec"
gosec -fmt sonarqube -out gosec.json -no-fail ./...
echo "---> gosec gosec.json"
cat gosec.json
if [ "${ISHIELD_ENV}" = remote ]; then \
    echo "--> Running sonar-scanner"; \
    sonar-scanner -Dproject.settings=${ISHIELD_REPO_ROOT}/sonar-project.properties --debug || echo "Sonar scanner is not available"; \
fi