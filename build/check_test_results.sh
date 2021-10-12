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

cd ${SHIELD_OP_DIR}
go test -v ./test/e2e | tee /tmp/e2e_results.txt

FAILURES=$(cat /tmp/e2e_results.txt | grep "FAIL:" | wc -c)

if [ ${FAILURES} -gt 0 ]; then
    cat /tmp/e2e_results.txt
    echo "One or more e2e tests failed. Failures: ${FAILURES}"
    echo "K8s events in ${TEST_NS}:"
    kubectl get event -n ${TEST_NS}
    exit 1
else
    echo "All e2e tests passed successfully."
    exit 0
fi

cd ${ISHIELD_REPO_ROOT}