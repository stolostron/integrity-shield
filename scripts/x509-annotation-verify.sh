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
  echo "Usage: $CMDNAME  <input-file> <CA-cert-file>" 1>&2
  exit 1
fi

if [ ! -e $2 ]; then
  echo "$2 does not exist"
  exit 1
fi

INPUT_FILE=$1
CA_CERT_FILE=$2

if ! [ -x "$(command -v yq)" ]; then
   echo 'Error: yq is not installed.' >&2
   exit 1
fi

if [ ! -f $INPUT_FILE ]; then
   echo "Input file does not exist, please create it."
   exit 1
fi

if [ ! -f $CA_CERT_FILE ]; then
   echo "CA cert file does not exist, please create it."
   exit 1
fi

if [ -z "$TMP_DIR" ]; then
    echo "TMP_DIR is empty. Setting /tmp as default"
    TMP_DIR="/tmp"
fi

if [ ! -d $TMP_DIR ]; then
    echo "$TMP_DIR directory does not exist, please create it."
    exit 1
fi

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    base='base64 -w 0'
    base_decode='base64 -d'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    base='base64'
    base_decode='base64 -D'
fi
gzip='gzip -c'
gzip_decode='gzip -d'

YQ_VERSION=$(yq --version 2>&1 | awk '{print $3}' | cut -c 1 )

if [[ $YQ_VERSION == "3" ]]; then
    msg=$(yq r -d0 ${INPUT_FILE} 'metadata.annotations."integrityshield.io/message"')
    sign=$(yq r -d0 ${INPUT_FILE} 'metadata.annotations."integrityshield.io/signature"')
    cert=$(yq r -d0 ${INPUT_FILE} 'metadata.annotations."integrityshield.io/certificate"')
elif [[ $YQ_VERSION == "4" ]]; then
    msg=$(yq eval '.metadata.annotations."integrityshield.io/message" | select(di == 0)' ${INPUT_FILE})
    sign=$(yq eval '.metadata.annotations."integrityshield.io/signature" | select(di == 0)' ${INPUT_FILE})
    cert=$(yq eval '.metadata.annotations."integrityshield.io/certificate" | select(di == 0)' ${INPUT_FILE})
fi


ISHIELD_TMP_DIR="${TMP_DIR}/ishield_tmp_dir"

if [ ! -d ${ISHIELD_TMP_DIR} ]; then
   mkdir -p  ${ISHIELD_TMP_DIR}
fi


ISHIELD_INPUT_FILE="${ISHIELD_TMP_DIR}/input.yaml"
ISHIELD_SIGN_FILE="${ISHIELD_TMP_DIR}/input.sig"
ISHIELD_MSG_FILE="${ISHIELD_TMP_DIR}/input.msg"
ISHIELD_CERT_FILE="${ISHIELD_TMP_DIR}/input.crt"
ISHIELD_PUBKEY_FILE="${ISHIELD_TMP_DIR}/input.pub"


cat ${INPUT_FILE} > ${ISHIELD_INPUT_FILE}

if [[ $YQ_VERSION == "3" ]]; then
   yq d -d* ${ISHIELD_INPUT_FILE} 'metadata.annotations."integrityshield.io/message"' -i
   yq d -d* ${ISHIELD_INPUT_FILE} 'metadata.annotations."integrityshield.io/signature"' -i
   yq d -d* ${ISHIELD_INPUT_FILE} 'metadata.annotations."integrityshield.io/certificate"' -i
   cnt=0
   yq r -d* ${ISHIELD_INPUT_FILE} -j | while read doc;
   do
      annotation_exist=$(echo $doc | yq r - 'metadata.annotations')
      if  [ "${annotation_exist}" == "{}" ]; then
          yq d -d${cnt} ${ISHIELD_INPUT_FILE} 'metadata.annotations' -i
      fi
      cnt=$[$cnt+1]
   done
elif [[ $YQ_VERSION == "4" ]]; then
   yq eval 'del(.metadata.annotations."integrityshield.io/message")' -i ${ISHIELD_INPUT_FILE}
   yq eval 'del(.metadata.annotations."integrityshield.io/signature")' -i ${ISHIELD_INPUT_FILE}
   yq eval 'del(.metadata.annotations."integrityshield.io/certificate")' -i ${ISHIELD_INPUT_FILE}
   cnt=0
   while true
   do
      kind=$(yq eval ".kind | select(di == $cnt)" ${ISHIELD_INPUT_FILE}  | sed 's/\//_/g')
      if [ -z "$kind" ]; then
          break
      fi
      annotation_exist=$(yq eval ".metadata.annotations | select(di == $cnt)" ${ISHIELD_INPUT_FILE})
      if  [ "${annotation_exist}" == "{}" ]; then
          yq eval "del(.metadata.annotations | select(di == $cnt))" -i ${ISHIELD_INPUT_FILE}
      fi
      cnt=$[$cnt+1]
   done
fi


msg_body=`cat ${ISHIELD_INPUT_FILE}`

msg_decoded=`echo $msg | $base_decode | $gzip_decode`

RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color


if [ "${msg_decoded}" != "${msg_body}" ]; then
   
   if [ -d ${ISHIELD_TMP_DIR} ]; then
     rm -rf ${ISHIELD_TMP_DIR}
   fi

   result="${RED}Verification: Failure${NC}"
   echo ""
   echo "Input file content has been changed."
   echo $result
   exit 1
fi

if [ -z ${msg} ] || [ -z ${sign} ] ; then
   result="${RED}Verification: Failure${NC}"
   echo ""
   echo "Input file is not yet signed."
   echo $result
   exit 1
else
   echo $msg | ${base_decode} | ${gzip_decode} >  ${ISHIELD_MSG_FILE}
   echo $sign | ${base_decode} > ${ISHIELD_SIGN_FILE}
   echo $cert | ${base_decode} | ${gzip_decode} > ${ISHIELD_CERT_FILE}

   # get pubkey from certificate
   openssl x509 -pubkey -noout -in ${ISHIELD_CERT_FILE} > ${ISHIELD_PUBKEY_FILE}

   openssl dgst -sha256 -verify ${ISHIELD_PUBKEY_FILE} -signature ${ISHIELD_SIGN_FILE} ${ISHIELD_MSG_FILE}  > /dev/null 2>&1 
   sigstatus=$?

   return_msg=""
   exit_status=1
   if [[ $sigstatus ]]; then
      openssl verify -CAfile ${CA_CERT_FILE} ${ISHIELD_CERT_FILE}  > /dev/null 2>&1 
      certstatus=$?
      if [[ $certstatus ]]; then
         return_msg="Signature is successfully verified."
         exit_status=0
      else
         return_msg="Certificate verification failed."
      fi
   else
      return_msg="Signature verification failed."
   fi

   result="${RED}Verification: Failure${NC}"
   if [ $exit_status == 0 ]; then
      result="${CYAN}Verification: Success${NC}"
   fi

   echo ""
   echo $return_msg
   echo $result
   exit $exit_status

fi


