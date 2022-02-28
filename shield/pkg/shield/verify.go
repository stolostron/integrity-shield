//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package shield

import (
	"encoding/json"
	"fmt"

	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	log "github.com/sirupsen/logrus"
	k8smnfconfig "github.com/stolostron/integrity-shield/shield/pkg/config"

	// ishieldimage "github.com/stolostron/integrity-shield/shield/pkg/image"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func ResourceVerify(resource, oldResource unstructured.Unstructured, username, operation string, commonProfile *k8smnfconfig.RequestFilterProfile, constraint *k8smnfconfig.ManifestIntegrityConstraint) (error, bool, string) {
	var rawObject, rawOldObject []byte
	rawObject, err := json.Marshal(resource)
	if err != nil {
		errMsg := "failed to marshal new resource: " + err.Error()
		return err, false, errMsg
	}
	if operation == "Update" {
		rawOldObject, err = json.Marshal(oldResource)
		if err != nil {
			errMsg := "failed to marshal old resource: " + err.Error()
			return err, false, errMsg
		}
	}
	commonSkipUserMatched := false
	skipObjectMatched := false

	//filter by user listed in common profile
	commonSkipUserMatched = commonProfile.SkipUsers.Match(resource, username)

	// skip object
	skipObjectMatched = skipObjectsMatch(commonProfile.SkipObjects, resource)

	// Proccess with parameter
	//filter by user
	skipUserMatched := constraint.SkipUsers.Match(resource, username)

	//force check user
	inScopeUserMatched := constraint.InScopeUsers.Match(resource, username)

	//check scope
	inScopeObjMatched := constraint.InScopeObjects.Match(resource)

	allow := false
	message := ""
	if (skipUserMatched || commonSkipUserMatched) && !inScopeUserMatched {
		allow = true
		message = "SkipUsers rule matched."
	} else if !inScopeObjMatched {
		allow = true
		message = "ObjectSelector rule did not match. Out of scope of verification."
	} else if skipObjectMatched {
		allow = true
		message = "SkipObjects rule matched."
	} else if operation == "UPDATE" {
		// mutation check
		ignoreFields := getMatchedIgnoreFields(constraint.IgnoreFields, commonProfile.IgnoreFields, resource)
		mutated, err := mutationCheck(rawOldObject, rawObject, ignoreFields)
		if err != nil {
			log.Errorf("failed to check mutation: %s", err.Error())
			message = "IntegrityShield failed to decide the response. Failed to check mutation: " + err.Error()
		}
		if !mutated {
			allow = true
			message = "no mutation found"
		}
	}
	if !allow { // signature check
		var signatureAnnotationType string
		annotations := resource.GetAnnotations()
		_, found := annotations[ImageRefAnnotationKeyShield]
		if found {
			signatureAnnotationType = SignatureAnnotationTypeShield
		}
		vo := setVerifyOption(constraint, commonProfile, signatureAnnotationType)
		log.WithFields(log.Fields{
			"namespace": resource.GetNamespace(),
			"name":      resource.GetName(),
			"kind":      resource.GetKind(),
			"operation": operation,
			"userName":  username,
		}).Debug("VerifyOption: ", vo)
		// call VerifyResource with resource, verifyOption, keypath, imageRef
		result, err := k8smanifest.VerifyResource(resource, vo)
		log.WithFields(log.Fields{
			"namespace": resource.GetNamespace(),
			"name":      resource.GetName(),
			"kind":      resource.GetKind(),
			"operation": operation,
			"userName":  username,
		}).Debug("VerifyResource result: ", result)
		if err != nil {
			log.WithFields(log.Fields{
				"namespace": resource.GetNamespace(),
				"name":      resource.GetName(),
				"kind":      resource.GetKind(),
				"operation": operation,
				"userName":  username,
			}).Warningf("Signature verification is required for this request, but verifyResource return error ; %s", err.Error())
			return nil, false, err.Error()
		}

		if result.InScope {
			if result.Verified {
				allow = true
				message = fmt.Sprintf("singed by a valid signer: %s", result.Signer)
			} else {
				allow = false
				message = "Signature verification is required for this request, but no signature is found."
				if result.Diff != nil && result.Diff.Size() > 0 {
					message = fmt.Sprintf("Signature verification is required for this request, but failed to verify signature. diff found: %s", result.Diff.String())
				} else if result.Signer != "" {
					message = fmt.Sprintf("Signature verification is required for this request, but no signer config matches with this resource. This is signed by %s", result.Signer)
				}
			}
		} else {
			allow = true
			message = "not protected"
		}

	}

	return nil, allow, message
}
