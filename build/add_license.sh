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
# limitations under the License

CMDNAME=`basename $0`
if [ $# -ne 2 ]; then
  echo "Usage: $CMDNAME <target-file> <license-file>" 1>&2
  exit 1
fi

if [ -z "$SHIELD_OP_DIR" ]; then
    echo "SHIELD_OP_DIR is empty. Please set env."
    exit 1
fi

targetFile=$1
licenseFile=$2

LICENSELEN=$(wc -l ${licenseFile} | cut -f1 -d ' ')

echo $LICENSELEN

head -$LICENSELEN ${targetFile} | diff ${licenseFile} - || ( ( cat ${licenseFile}; echo; cat ${targetFile}) > ${SHIELD_OP_DIR}/file; mv ${SHIELD_OP_DIR}/file ${targetFile})
