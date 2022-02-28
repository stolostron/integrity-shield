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
	"strings"

	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	log "github.com/sirupsen/logrus"
	k8smnfconfig "github.com/stolostron/integrity-shield/shield/pkg/config"

	// ishieldimage "github.com/stolostron/integrity-shield/shield/pkg/image"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func ResourceVerify(resource, oldResource unstructured.Unstructured, username, operation string, commonProfile *k8smnfconfig.RequestFilterProfile, constraint *k8smnfconfig.ManifestIntegrityConstraint) (error, bool, string) {
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
		var rawObject, rawOldObject []byte
		rawObject, err := json.Marshal(resource)
		if err != nil {
			errMsg := "failed to marshal new resource: " + err.Error()
			return err, false, errMsg
		}

		rawOldObject, err = json.Marshal(oldResource)
		if err != nil {
			errMsg := "failed to marshal old resource: " + err.Error()
			return err, false, errMsg
		}

		ignoreFields := getMatchedIgnoreFields(constraint.IgnoreFields, commonProfile.IgnoreFields, resource)
		mutated, err := mutationCheck(rawOldObject, rawObject, ignoreFields)
		if err != nil {
			log.Errorf("failed to check mutation: %s", err.Error())
			message = "IntegrityShield failed to decide the response. Failed to check mutation: " + err.Error()
			return err, false, message
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

func setVerifyOption(paramObj *k8smnfconfig.ManifestIntegrityConstraint, commonProfile *k8smnfconfig.RequestFilterProfile, signatureAnnotationType string) *k8smanifest.VerifyResourceOption {
	// get verifyOption and imageRef from Parameter
	vo := &paramObj.VerifyResourceOption

	// set Signature ref
	if paramObj.SignatureRef.ImageRef != "" {
		vo.ImageRef = paramObj.SignatureRef.ImageRef
	}
	if paramObj.SignatureRef.SignatureResourceRef.Name != "" && paramObj.SignatureRef.SignatureResourceRef.Namespace != "" {
		ref := fmt.Sprintf("k8s://ConfigMap/%s/%s", paramObj.SignatureRef.SignatureResourceRef.Namespace, paramObj.SignatureRef.SignatureResourceRef.Name)
		vo.SignatureResourceRef = ref
	}
	if paramObj.SignatureRef.ProvenanceResourceRef.Name != "" && paramObj.SignatureRef.ProvenanceResourceRef.Namespace != "" {
		ref := fmt.Sprintf("k8s://ConfigMap/%s/%s", paramObj.SignatureRef.ProvenanceResourceRef.Namespace, paramObj.SignatureRef.ProvenanceResourceRef.Name)
		vo.ProvenanceResourceRef = ref
	}

	// set DryRun namespace
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	vo.DryRunNamespace = namespace

	// set Signature type
	if signatureAnnotationType == SignatureAnnotationTypeShield {
		vo.AnnotationConfig.AnnotationKeyDomain = AnnotationKeyDomain
	}
	// prepare local key for verifyResource
	if len(paramObj.KeyConfigs) != 0 {
		keyPathList := []string{}
		for _, keyconfig := range paramObj.KeyConfigs {
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
	if len(commonProfile.IgnoreFields) == 0 {
		return vo
	}
	fields := k8smanifest.ObjectFieldBindingList{}
	fields = append(fields, vo.IgnoreFields...)
	fields = append(fields, commonProfile.IgnoreFields...)
	vo.IgnoreFields = fields
	return vo
}
