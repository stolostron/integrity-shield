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
FROM registry.access.redhat.com/ubi7/ubi-minimal:7.9

RUN mkdir /ishield-op-app && \
    curl -L https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -o jq-linux64 && \
    chmod +x jq-linux64 && \
    mv jq-linux64 /usr/local/bin/jq


COPY build/_output/bin/integrity-shield-operator /ishield-op-app/manager
ADD bundle/manifests/integrity-shield-operator.clusterserviceversion.yaml /ishield-op-app/bundle/manifests/integrity-shield-operator.clusterserviceversion.yaml

RUN chgrp -R 0 /ishield-op-app && chmod -R g=u /ishield-op-app

WORKDIR /ishield-op-app

ENTRYPOINT ["/ishield-op-app/manager"]
