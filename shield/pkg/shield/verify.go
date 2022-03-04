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
	"os"
	"strconv"
	"strings"

	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	log "github.com/sirupsen/logrus"
	config "github.com/stolostron/integrity-shield/shield/pkg/config"
	ishieldimage "github.com/stolostron/integrity-shield/shield/pkg/image"
	admission "k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const SignatureAnnotationKeyShield = "integrityshield.io/signature"
const AnnotationKeyDomainShield = "integrityshield.io"
const SignatureAnnotationTypeShield = "IntegrityShield"
const SignatureResourceLabel = "integrityshield.io/signatureResource"

// Allow message
var (
	SkipUser          = "Allowed by skipUsers rule."
	NoMutation        = "Allowed because no mutation found."
	SkipObject        = "Allowed by skipObjects rule."
	NonScopeObject    = "Allowed because this resource is not in-scope."
	SignatureResource = "Allowed because this resource is signatureResource."
)

// VerifyResource checks if manifest is valid based on signature, ManifestVerifyRule and RequestFilterProfile which is included in ManifestVerifyConfig.
// VerifyResource uses the default profile if ManifestVerifyConfig input is nil.
func VerifyResource(request *admission.AdmissionRequest, mvconfig *config.ManifestVerifyConfig, rule *config.ManifestVerifyRule) (allow bool, message string, err error) {
	// log setting
	logLevelStr := os.Getenv(config.LogLevelEnvKey)
	logLevel, ok := config.LogLevelMap[logLevelStr]
	if !ok {
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)

	// prepare ManifestVerifyConfig/RequestFilterProfile if nil
	if mvconfig == nil {
		log.Info("ManifestVerifyConfig is nil. Use default config.")
		mvconfig = config.NewManifestVerifyConfig("ishield-dryrun-ns")
	}
	if mvconfig.RequestFilterProfile == nil {
		log.Info("RequestFilterProfile is nil. Use default profile.")
		mvconfig = config.NewManifestVerifyConfig(mvconfig.DryRunNamespcae)
	}

	log.WithFields(log.Fields{
		"namespace": request.Namespace,
		"name":      request.Name,
		"kind":      request.Kind.Kind,
		"operation": request.Operation,
		"userName":  request.UserInfo.Username,
	}).Info("Start manifest verification.")

	// unmarshal admission request object
	var resource unstructured.Unstructured
	objectBytes := request.Object.Raw
	err = json.Unmarshal(objectBytes, &resource)
	if err != nil {
		log.Errorf("Failed to Unmarshal a requested object into %T; %s", resource, err.Error())
		errMsg := "IntegrityShield failed to decide the response. Failed to Unmarshal a requested object: " + err.Error()
		return false, errMsg, err
	}

	commonSkipUserMatched := false
	skipObjectMatched := false
	signatureResource := false

	// check if signature resource
	signatureResource = isAllowedSignatureResource(resource, request.OldObject.Raw, request.Operation)

	//filter by user listed in common profile
	commonSkipUserMatched = mvconfig.RequestFilterProfile.SkipUsers.Match(resource, request.UserInfo.Username)

	// skip object
	skipObjectMatched = skipObjectsMatch(mvconfig.RequestFilterProfile.SkipObjects, resource)

	// Proccess with parameter
	//filter by user
	skipUserMatched := rule.SkipUsers.Match(resource, request.UserInfo.Username)

	//force check user
	inScopeUserMatched := rule.InScopeUsers.Match(resource, request.UserInfo.Username)

	//check scope
	inScopeObjMatched := rule.InScopeObjects.Match(resource)

	allow = false
	message = ""
	if signatureResource {
		allow = true
		message = SignatureResource
	} else if (skipUserMatched || commonSkipUserMatched) && !inScopeUserMatched {
		allow = true
		message = SkipUser
	} else if !inScopeObjMatched {
		allow = true
		message = NonScopeObject
	} else if skipObjectMatched {
		allow = true
		message = SkipObject
	} else if isUpdateRequest(request.Operation) {
		// mutation check
		ignoreFields := getMatchedIgnoreFields(rule.IgnoreFields, mvconfig.RequestFilterProfile.IgnoreFields, resource)
		mutated, err := mutationCheck(request.Object.Raw, request.OldObject.Raw, ignoreFields)
		if err != nil {
			log.Errorf("Failed to check mutation: %s", err.Error())
			message = "IntegrityShield failed to decide the response. Failed to check mutation: " + err.Error()
		}
		if !mutated {
			allow = true
			message = NoMutation
		}
	}

	if !allow { // signature check
		var signatureAnnotationType string
		annotations := resource.GetAnnotations()
		_, found := annotations[SignatureAnnotationKeyShield]
		if found {
			signatureAnnotationType = SignatureAnnotationTypeShield
		}
		vo, err := setVerifyOption(rule, mvconfig, signatureAnnotationType)
		if err != nil {
			return false, err.Error(), nil
		}
		log.WithFields(log.Fields{
			"namespace": request.Namespace,
			"name":      request.Name,
			"kind":      request.Kind.Kind,
			"operation": request.Operation,
			"userName":  request.UserInfo.Username,
		}).Debug("VerifyOption: ", vo)
		// call VerifyResource with resource, verifyOption, keypath, imageRef
		result, err := k8smanifest.VerifyResource(resource, vo)
		log.WithFields(log.Fields{
			"namespace": request.Namespace,
			"name":      request.Name,
			"kind":      request.Kind.Kind,
			"operation": request.Operation,
			"userName":  request.UserInfo.Username,
		}).Debug("VerifyResource result: ", result)
		if err != nil {
			log.WithFields(log.Fields{
				"namespace": request.Namespace,
				"name":      request.Name,
				"kind":      request.Kind.Kind,
				"operation": request.Operation,
				"userName":  request.UserInfo.Username,
			}).Warningf("Signature verification is required for this request, but verifyResource return error ; %s", err.Error())
			return false, err.Error(), nil
		}

		if result.InScope {
			if result.Verified {
				allow = true
				message = fmt.Sprintf("Singed by a valid signer: %s", result.Signer)
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
			message = NonScopeObject
		}

	}
	log.WithFields(log.Fields{
		"namespace": request.Namespace,
		"name":      request.Name,
		"kind":      request.Kind.Kind,
		"operation": request.Operation,
		"userName":  request.UserInfo.Username,
	}).Infof("Completed manifest verification: allow %s: %s", strconv.FormatBool(allow), message)
	return allow, message, nil
}

func mutationCheck(rawOldObject, rawObject []byte, IgnoreFields []string) (bool, error) {
	var oldObject *mapnode.Node
	var newObject *mapnode.Node
	mask := []string{
		"metadata.annotations.namespace",
		"metadata.annotations.kubectl.\"kubernetes.io/last-applied-configuration\"",
		"metadata.annotations.deprecated.daemonset.template.generation",
		"metadata.creationTimestamp",
		"metadata.uid",
		"metadata.generation",
		"metadata.managedFields",
		"metadata.selfLink",
		"metadata.resourceVersion",
		"status",
	}
	if v, err := mapnode.NewFromBytes(rawObject); err != nil || v == nil {
		return false, err
	} else {
		v = v.Mask(mask)
		obj := v.ToMap()
		newObject, _ = mapnode.NewFromMap(obj)
	}
	if v, err := mapnode.NewFromBytes(rawOldObject); err != nil || v == nil {
		return false, err
	} else {
		v = v.Mask(mask)
		oldObj := v.ToMap()
		oldObject, _ = mapnode.NewFromMap(oldObj)
	}
	// diff
	dr := oldObject.Diff(newObject)
	if dr == nil || dr.Size() == 0 {
		return false, nil
	}
	// ignoreField check
	unfiltered := &mapnode.DiffResult{}
	if dr != nil && dr.Size() > 0 {
		_, unfiltered, _ = dr.Filter(IgnoreFields)
	}
	if unfiltered.Size() == 0 {
		return false, nil
	}
	return true, nil
}

func setVerifyOption(constraint *config.ManifestVerifyRule, mvconfig *config.ManifestVerifyConfig, signatureAnnotationType string) (*k8smanifest.VerifyResourceOption, error) {
	// get verifyOption and imageRef from Parameter
	vo := &constraint.VerifyResourceOption

	// set Signature ref
	if constraint.SignatureRef.ImageRef != "" {
		vo.ImageRef = constraint.SignatureRef.ImageRef
	}
	if constraint.SignatureRef.SignatureResourceRef.Name != "" && constraint.SignatureRef.SignatureResourceRef.Namespace != "" {
		ref := fmt.Sprintf("k8s://ConfigMap/%s/%s", constraint.SignatureRef.SignatureResourceRef.Namespace, constraint.SignatureRef.SignatureResourceRef.Name)
		vo.SignatureResourceRef = ref
	}
	if constraint.SignatureRef.ProvenanceResourceRef.Name != "" && constraint.SignatureRef.ProvenanceResourceRef.Namespace != "" {
		ref := fmt.Sprintf("k8s://ConfigMap/%s/%s", constraint.SignatureRef.ProvenanceResourceRef.Namespace, constraint.SignatureRef.ProvenanceResourceRef.Name)
		vo.ProvenanceResourceRef = ref
	}

	// set DryRun namespace
	vo.DryRunNamespace = mvconfig.DryRunNamespcae
	if vo.DryRunNamespace == "" {
		vo.DryRunNamespace = config.DefaultDryRunNS
	}

	// set Signature type
	if signatureAnnotationType == SignatureAnnotationTypeShield {
		vo.AnnotationConfig.AnnotationKeyDomain = AnnotationKeyDomainShield
	}

	// prepare local key for verifyResource
	if len(constraint.KeyConfigs) != 0 {
		keyPathList := []string{}
		for _, keyconfig := range constraint.KeyConfigs {
			if keyconfig.Secret.Namespace != "" && keyconfig.Secret.Name != "" {
				if keyconfig.Secret.Mount {
					keyPath, err := keyconfig.LoadKeySecret()
					if err != nil {
						log.Errorf("Failed to load key secret: %s", err.Error())
						return nil, fmt.Errorf("Failed to load key secret: %s", err.Error())
					}
					keyPathList = append(keyPathList, keyPath)
				} else {
					keyRef := keyconfig.ConvertToCosignKeyRef()
					keyPathList = append(keyPathList, keyRef)
				}
			}
			if keyconfig.Key.PEM != "" && keyconfig.Key.Name != "" {
				keyPath, err := keyconfig.ConvertToLocalFilePath()
				if err != nil {
					return nil, fmt.Errorf("Failed to get local file path: %s", err.Error())
				}
				keyPathList = append(keyPathList, keyPath)
			}
		}
		if len(keyPathList) == 0 {
			return nil, fmt.Errorf("KeyConfigs is not properly configured, failed to set public key.")
		}
		keyPathString := strings.Join(keyPathList, ",")
		if keyPathString != "" {
			vo.KeyPath = keyPathString
		}
	}
	// merge params in common profile
	if len(mvconfig.RequestFilterProfile.IgnoreFields) == 0 {
		return vo, nil
	}
	fields := k8smanifest.ObjectFieldBindingList{}
	fields = append(fields, vo.IgnoreFields...)
	fields = append(fields, mvconfig.RequestFilterProfile.IgnoreFields...)
	vo.IgnoreFields = fields
	return vo, nil
}

func skipObjectsMatch(l k8smanifest.ObjectReferenceList, obj unstructured.Unstructured) bool {
	if len(l) == 0 {
		return false
	}
	for _, r := range l {
		if r.Match(obj) {
			return true
		}
	}
	return false
}

func getMatchedIgnoreFields(pi, ci k8smanifest.ObjectFieldBindingList, resource unstructured.Unstructured) []string {
	var allIgnoreFields []string
	_, fields := pi.Match(resource)
	_, commonfields := ci.Match(resource)
	allIgnoreFields = append(allIgnoreFields, fields...)
	allIgnoreFields = append(allIgnoreFields, commonfields...)
	return allIgnoreFields
}

func isAllowedSignatureResource(resource unstructured.Unstructured, oldResourceRaw []byte, operation admission.Operation) bool {
	if resource.GetKind() != "ConfigMap" {
		return false
	}
	if isCreateRequest(operation) {
		return isSignatureResource(resource)
	} else if isUpdateRequest(operation) {
		// unmarshal admission request object
		var oldResource unstructured.Unstructured
		err := json.Unmarshal(oldResourceRaw, &resource)
		if err != nil {
			log.Errorf("Failed to signature resource check: Unmarshal a requested old object into %T; %s", resource, err.Error())
			return false
		}
		return (isSignatureResource(resource) && isSignatureResource(oldResource))
	}
	return false
}

func isSignatureResource(resource unstructured.Unstructured) bool {
	labelsMap := resource.GetLabels()
	_, found := labelsMap[SignatureResourceLabel]
	return found
}

func isUpdateRequest(operation admission.Operation) bool {
	return (operation == admission.Update)
}

func isCreateRequest(operation admission.Operation) bool {
	return (operation == admission.Create)
}

// Image verification
func VerifyImagesInManifest(request *admission.AdmissionRequest, imageProfile config.ImageProfile) (bool, string) {
	// unmarshal admission request object
	var resource unstructured.Unstructured
	objectBytes := request.Object.Raw
	err := json.Unmarshal(objectBytes, &resource)
	if err != nil {
		log.Errorf("Failed to Unmarshal a requested object into %T; %s", resource, err.Error())
		errMsg := "IntegrityShield failed to decide the response. Failed to Unmarshal a requested object: " + err.Error()
		return false, errMsg
	}

	imageAllow := true
	imageMessage := ""
	var imageVerifyResults []ishieldimage.ImageVerifyResult
	if imageProfile.Enabled() {
		_, err := ishieldimage.VerifyImageInManifest(resource, imageProfile)
		if err != nil {
			log.Errorf("Failed to verify images: %s", err.Error())
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
	return imageAllow, imageMessage
}
