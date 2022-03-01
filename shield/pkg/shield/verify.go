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
	"strings"

	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	log "github.com/sirupsen/logrus"
	k8smnfconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	ishieldimage "github.com/stolostron/integrity-shield/shield/pkg/image"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func VerifyResource(resource, oldResource unstructured.Unstructured, username, operation string, maniconfig *k8smnfconfig.ManifestVerifyConfig, constraint *k8smnfconfig.ManifestIntegrityConstraint) (error, bool, string) {
	commonSkipUserMatched := false
	skipObjectMatched := false
	signatureResource := false

	// check if signature resource
	signatureResource = isAllowedSignatureResource(resource, oldResource, operation)

	//filter by user listed in common profile
	commonSkipUserMatched = maniconfig.RequestFilterProfile.SkipUsers.Match(resource, username)

	// skip object
	skipObjectMatched = skipObjectsMatch(maniconfig.RequestFilterProfile.SkipObjects, resource)

	// Proccess with parameter
	//filter by user
	skipUserMatched := constraint.SkipUsers.Match(resource, username)

	//force check user
	inScopeUserMatched := constraint.InScopeUsers.Match(resource, username)

	//check scope
	inScopeObjMatched := constraint.InScopeObjects.Match(resource)

	allow := false
	message := ""
	if signatureResource {
		allow = true
		message = "Allowed because this resource is signatureResource."
	} else if (skipUserMatched || commonSkipUserMatched) && !inScopeUserMatched {
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
		var rawObject, rawOldObject []byte
		rawObject, err := json.Marshal(resource)
		if err != nil {
			errMsg := "Failed to check mutation: Failed to marshal new resource: " + err.Error()
			return err, false, errMsg
		}

		rawOldObject, err = json.Marshal(oldResource)
		if err != nil {
			errMsg := "Failed to check mutation: Failed to marshal old resource: " + err.Error()
			return err, false, errMsg
		}

		ignoreFields := getMatchedIgnoreFields(constraint.IgnoreFields, maniconfig.RequestFilterProfile.IgnoreFields, resource)
		mutated, err := mutationCheck(rawOldObject, rawObject, ignoreFields)
		if err != nil {
			log.Errorf("Failed to check mutation: %s", err.Error())
			message = "IntegrityShield failed to decide the response. Failed to check mutation: " + err.Error()
		}
		if !mutated {
			allow = true
			message = "No mutation found"
		}
	}

	if !allow { // signature check
		var signatureAnnotationType string
		annotations := resource.GetAnnotations()
		_, found := annotations[ImageRefAnnotationKeyShield]
		if found {
			signatureAnnotationType = SignatureAnnotationTypeShield
		}
		vo := setVerifyOption(constraint, maniconfig, signatureAnnotationType)
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
			message = "Not protected"
		}

	}

	return nil, allow, message
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

func setVerifyOption(constraint *k8smnfconfig.ManifestIntegrityConstraint, maniConfig *k8smnfconfig.ManifestVerifyConfig, signatureAnnotationType string) *k8smanifest.VerifyResourceOption {
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
	vo.DryRunNamespace = maniConfig.DryRunNamespcae

	// set Signature type
	if signatureAnnotationType == SignatureAnnotationTypeShield {
		vo.AnnotationConfig.AnnotationKeyDomain = AnnotationKeyDomain
	}
	// prepare local key for verifyResource
	if len(constraint.KeyConfigs) != 0 {
		keyPathList := []string{}
		for _, keyconfig := range constraint.KeyConfigs {
			if keyconfig.KeySecretName != "" {
				keyPath, err := k8smnfconfig.LoadKeySecret(keyconfig.KeySecretNamespace, keyconfig.KeySecretName)
				if err != nil {
					log.Errorf("failed to load key secret: %s", err.Error())
				}
				keyPathList = append(keyPathList, keyPath)
			}
		}
		keyPathString := strings.Join(keyPathList, ",")
		if keyPathString != "" {
			vo.KeyPath = keyPathString
		}
	}
	// merge params in common profile
	if len(maniConfig.RequestFilterProfile.IgnoreFields) == 0 {
		return vo
	}
	fields := k8smanifest.ObjectFieldBindingList{}
	fields = append(fields, vo.IgnoreFields...)
	fields = append(fields, maniConfig.RequestFilterProfile.IgnoreFields...)
	vo.IgnoreFields = fields
	return vo
}

func isAllowedSignatureResource(resource, oldResource unstructured.Unstructured, operation string) bool {
	var currentResourceLabel bool
	var label bool
	if !(resource.GetKind() == "ConfigMap") {
		return label
	}
	label = isSignatureResource(resource)
	if operation == "CREATE" {
		currentResourceLabel = true
	} else if operation == "UPDATE" {
		currentResourceLabel = isSignatureResource(oldResource)
	}
	return (label && currentResourceLabel)
}

func isSignatureResource(resource unstructured.Unstructured) bool {
	var label bool
	labelsMap := resource.GetLabels()
	_, found := labelsMap[SignatureResourceLabel]
	if found {
		label = true
	}
	return label
}

func VerifyImagesInManifest(resource unstructured.Unstructured, imageProfile k8smnfconfig.ImageProfile) (bool, string) {
	imageAllow := true
	imageMessage := ""
	var imageVerifyResults []ishieldimage.ImageVerifyResult
	if imageProfile.Enabled() {
		_, err := ishieldimage.VerifyImageInManifest(resource, imageProfile)
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
	return imageAllow, imageMessage
}
