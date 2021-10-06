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
#!/bin/bash
CMDNAME=`basename $0`
if [ $# -ne 2 ]; then
  echo "Usage: $CMDNAME <YAML files directory> <pubring-key>" 1>&2
  exit 1
fi
if [ ! -e $3 ]; then
  echo "$3 does not exist"
  exit 1
fi
SCRIPT_DIR=$(cd $(dirname $0); pwd)
TARGET_DIR=$1
PUBRING_KEY=$2

find ${TARGET_DIR} -type f -name "*.yaml" | while read file;
do
  echo "Verifying signature annotation in ${file}"

  $SCRIPT_DIR/../gpg-annotation-verify.sh  "$file" ${PUBRING_KEY}

done
