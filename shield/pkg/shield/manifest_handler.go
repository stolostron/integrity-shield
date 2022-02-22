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
	ishieldimage "github.com/stolostron/integrity-shield/shield/pkg/image"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func ManifestVerify(resource, oldResource unstructured.Unstructured, username, operation string, paramObj *k8smnfconfig.ParameterObject) (error, bool, string) {
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

	// load request handler consfig
	rhconfig, err := k8smnfconfig.LoadRequestHandlerConfig()
	if err != nil {
		log.Errorf("failed to load request handler config: %s", err.Error())
		errMsg := "IntegrityShield failed to decide the response. Failed to load request handler config: " + err.Error()
		return err, false, errMsg
	}
	if rhconfig == nil {
		log.Warning("request handler config is empty")
		rhconfig = &k8smnfconfig.RequestHandlerConfig{}
	}

	// setup log
	k8smnfconfig.SetupLogger(rhconfig.Log)
	// decisionReporter := k8smnfconfig.InitDecisionReporter(rhconfig.DecisionReporterConfig)
	// if paramObj.ConstraintName == "" {
	// 	log.Warning("ConstraintName is empty. Please set constraint name in parameter field.")
	// }
	// logRecord := map[string]interface{}{
	// 	"namespace":      req.Namespace,
	// 	"name":           req.Name,
	// 	"apiGroup":       req.RequestResource.Group,
	// 	"apiVersion":     req.RequestResource.Version,
	// 	"kind":           req.Kind.Kind,
	// 	"resource":       req.RequestResource.Resource,
	// 	"userName":       req.UserInfo.Username,
	// 	"constraintName": paramObj.ConstraintName,
	// 	"admissionTime":  time.Now().Format(timeFormat),
	// }

	log.WithFields(log.Fields{
		"namespace": resource.GetNamespace(),
		"name":      resource.GetName(),
		"kind":      resource.GetKind(),
		"operation": operation,
		"userName":  username,
	}).Info("Process new request")

	// get enforce action
	enforce := false
	if paramObj.Action == nil {
		if rhconfig.DefaultConstraintAction.Mode != "" {
			if rhconfig.DefaultConstraintAction.Mode == "enforce" {
				enforce = true
			}
		}
	} else {
		if paramObj.Action.Mode != "enforce" && paramObj.Action.Mode != "inform" {
			log.WithFields(log.Fields{
				"namespace": resource.GetNamespace(),
				"name":      resource.GetName(),
				"kind":      resource.GetKind(),
				"operation": operation,
				"userName":  username,
			}).Warningf("run mode should be set to 'enforce' or 'inform' in rule,%s", paramObj.ConstraintName)
		}
		if paramObj.Action.Mode == "enforce" {
			enforce = true
		}
	}
	if enforce {
		log.Info("enforce action is enabled.")
	} else {
		log.Info("enforce action is disabled.")
	}

	commonSkipUserMatched := false
	skipObjectMatched := false
	signatureResource := false

	// // check if signature resource
	// signatureResource = isAllowedSignatureResource(resource, req.AdmissionRequest.OldObject.Raw, req.Operation)

	//filter by user listed in common profile
	commonSkipUserMatched = rhconfig.RequestFilterProfile.SkipUsers.Match(resource, username)

	// skip object
	skipObjectMatched = skipObjectsMatch(rhconfig.RequestFilterProfile.SkipObjects, resource)

	// Proccess with parameter
	//filter by user
	skipUserMatched := paramObj.SkipUsers.Match(resource, username)

	//force check user
	inScopeUserMatched := paramObj.InScopeUsers.Match(resource, username)

	//check scope
	inScopeObjMatched := paramObj.InScopeObjects.Match(resource)

	allow := false
	message := ""
	if signatureResource {
		allow = true
		message = "allowed because this resource is signatureResource."
	} else if (skipUserMatched || commonSkipUserMatched) && !inScopeUserMatched {
		allow = true
		message = "SkipUsers rule matched."
		// logRecord["reason"] = message
		// logRecord["allow"] = allow
		// decisionReporter.SendLog(logRecord)
	} else if !inScopeObjMatched {
		allow = true
		message = "ObjectSelector rule did not match. Out of scope of verification."
	} else if skipObjectMatched {
		allow = true
		message = "SkipObjects rule matched."
	} else if operation == "UPDATE" {
		// mutation check
		ignoreFields := getMatchedIgnoreFields(paramObj.IgnoreFields, rhconfig.RequestFilterProfile.IgnoreFields, resource)
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
		vo := setVerifyOption(paramObj, rhconfig, signatureAnnotationType)
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
			// r := makeResultFromRequestHandler(false, err.Error(), enforce, req)
			// generate events
			// if rhconfig.SideEffectConfig.CreateDenyEvent {
			// 	_ = createOrUpdateEvent(req, r, paramObj.ConstraintName)
			// }
			// return r
			return err, false, err.Error()
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

		// image verify
		imageAllow := true
		imageMessage := ""
		var imageVerifyResults []ishieldimage.ImageVerifyResult
		if paramObj.ImageProfile.Enabled() {
			_, err = ishieldimage.VerifyImageInManifest(resource, paramObj.ImageProfile)
			if err != nil {
				log.Errorf("failed to verify images: %s", err.Error())
				imageAllow = false
				imageMessage = "Image signature verification is required, but failed to verify signature: " + err.Error()

			} else {
				for _, res := range imageVerifyResults {
					if res.InScope && !res.Verified {
						imageAllow = false
						imageMessage = "Image signature verification is required, but failed to verify signature: " + res.FailReason
						break
					}
				}
			}
		}

		if allow && !imageAllow {
			message = imageMessage
			allow = false
		}
	}

	// r := makeResultFromRequestHandler(allow, message, enforce, req)

	// // generate events
	// if rhconfig.SideEffectConfig.CreateDenyEvent {
	// 	_ = createOrUpdateEvent(req, r, paramObj.ConstraintName)
	// }
	// return r
	return nil, allow, message
}
