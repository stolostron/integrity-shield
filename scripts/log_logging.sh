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

if [ -z "$ISHIELD_NS" ]; then
    echo "ISHIELD_NS is empty. Please set namespace name for integrity-shield."
    exit 1
fi

ISHIELD_SERVER_POD=`kubectl get pod -n ${ISHIELD_NS} | grep integrity-shield-api | grep Running | awk '{print $1}'`
if [ -z "$ISHIELD_SERVER_POD" ]; then
    echo "ISHIELD_SERVER_POD is empty. There is no running integrity-shield-api"
    exit 1
fi

kubectl logs -f -n ${ISHIELD_NS} ${ISHIELD_SERVER_POD} -c integrity-shield-logger