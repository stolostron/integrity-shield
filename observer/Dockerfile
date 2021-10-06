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

RUN mkdir /ishield-app && mkdir /ishield-app/resources

COPY build/_bin/ishield-observer /ishield-app/observer

RUN chgrp -R 0 /ishield-app && chmod -R g=u /ishield-app

WORKDIR /ishield-app

ENTRYPOINT ["/ishield-app/observer"]
