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
  echo "Usage: $CMDNAME <signer> <YAML files directory>" 1>&2
  exit 1
fi
if [ ! -e $2 ]; then
  echo "$2 does not exist"
  exit 1
fi
SCRIPT_DIR=$(cd $(dirname $0); pwd)
SIGNER=$1
TARGET_DIR=$2
find ${TARGET_DIR} -type f -name "*.yaml" | while read file;
do
  cp ${file} ${file}.backup
  echo Original file is backed up as ${file}.backup

  $SCRIPT_DIR/../gpg-annotation-sign.sh ${SIGNER} "$file"

  echo Signature annotation is attached in $file.
done
