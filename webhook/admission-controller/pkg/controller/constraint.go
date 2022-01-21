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

package controller

import (
	"context"
	"encoding/json"

	k8smnfconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	"github.com/stolostron/integrity-shield/shield/pkg/shield"
	miprofile "github.com/stolostron/integrity-shield/webhook/admission-controller/pkg/apis/manifestintegrityprofile/v1"
	mipclient "github.com/stolostron/integrity-shield/webhook/admission-controller/pkg/client/manifestintegrityprofile/clientset/versioned/typed/manifestintegrityprofile/v1"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	kubeclient "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func GetParametersFromConstraint(constraint miprofile.ManifestIntegrityProfileSpec) *k8smnfconfig.ParameterObject {
	return &constraint.Parameters
}

func LoadConstraints() ([]miprofile.ManifestIntegrityProfile, error) {
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, nil
	}
	clientset, err := mipclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil, nil
	}
	miplist, err := clientset.ManifestIntegrityProfiles().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error("failed to get ManifestIntegrityProfiles:", err.Error())
		return nil, nil
	}
	return miplist.Items, nil
}

// Match
func matchCheck(req admission.Request, match miprofile.MatchCondition) bool {
	// check if excludedNamespace
	if len(match.ExcludedNamespaces) != 0 {
		for _, ens := range match.ExcludedNamespaces {
			if k8smnfutil.MatchPattern(ens, req.Namespace) {
				return false
			}
		}
	}
	// check if matched kinds/namespace/label
	var nsMatched bool
	var kindsMatched bool
	var labelMatched bool
	var nslabelMatched bool
	nsMatched = checkNamespaceMatch(req, match.Namespaces)
	kindsMatched = checkKindMatch(req, match.Kinds)
	labelMatched = checkLabelMatch(req, match.LabelSelector)
	nslabelMatched = checkNamespaceLabelMatch(req.Namespace, match.NamespaceSelector)

	if nsMatched && kindsMatched && nslabelMatched && labelMatched {
		return true
	}
	return false
}

func checkNamespaceLabelMatch(namespace string, labelSelector *metav1.LabelSelector) bool {
	if labelSelector == nil {
		return true
	}
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return false
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return false
	}
	ns, err := clientset.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	if err != nil {
		log.Errorf("failed to get a namespace `%s`:`%s`", namespace, err.Error())
		return false
	}
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		log.Errorf("failed to convert the LabelSelector api type into a struct that implements labels.Selector; %s", err.Error())
		return false
	}
	labelsMap := ns.GetLabels()
	labelsSet := labels.Set(labelsMap)
	matched := selector.Matches(labelsSet)
	return matched
}

func checkLabelMatch(req admission.Request, labelSelector *metav1.LabelSelector) bool {
	if labelSelector == nil {
		return true
	}
	var resource unstructured.Unstructured
	objectBytes := req.AdmissionRequest.Object.Raw
	err := json.Unmarshal(objectBytes, &resource)
	if err != nil {
		log.Errorf("failed to Unmarshal a requested object into %T; %s", resource, err.Error())
		return false
	}
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		log.Errorf("failed to convert the LabelSelector api type into a struct that implements labels.Selector; %s", err.Error())
		return false
	}
	labelsMap := resource.GetLabels()
	labelsSet := labels.Set(labelsMap)
	matched := selector.Matches(labelsSet)
	return matched
}

func checkNamespaceMatch(req admission.Request, match []string) bool {
	matched := false
	if len(match) == 0 {
		matched = true
	} else {
		// check if cluster scope
		if req.Namespace == "" {
			matched = true
		}
		for _, ns := range match {
			if k8smnfutil.MatchPattern(ns, req.Namespace) {
				matched = true
			}
		}
	}
	return matched
}

func checkKindMatch(req admission.Request, match []miprofile.Kinds) bool {
	matched := false
	if len(match) == 0 {
		matched = true
	} else {
		for _, kinds := range match {
			kind := false
			group := false
			if len(kinds.Kinds) == 0 {
				kind = true
			} else {
				for _, k := range kinds.Kinds {
					if k8smnfutil.MatchPattern(k, req.Kind.Kind) {
						kind = true
					}
				}
			}
			if len(kinds.ApiGroups) == 0 {
				group = true
			} else {
				for _, g := range kinds.ApiGroups {
					if k8smnfutil.MatchPattern(g, req.Kind.Group) {
						group = true
					}
				}
			}
			if kind && group {
				matched = true
			}
		}
	}
	return matched
}

// Status
func updateConstraintStatus(constraint string, req admission.Request, errMsg string) error {
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		log.Error(err)
		return err
	}
	clientset, err := mipclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return err
	}
	mip, err := clientset.ManifestIntegrityProfiles().Get(context.Background(), constraint, metav1.GetOptions{})
	if err != nil {
		log.Error("failed to get ManifestIntegrityProfiles:", err.Error())
		return err
	}
	newMIP := mip.UpdateStatus(req, errMsg)
	_, err = clientset.ManifestIntegrityProfiles().Update(context.Background(), newMIP, metav1.UpdateOptions{})
	if err != nil {
		log.Error("failed to update ManifestIntegrityProfileStatus:", err.Error())
		return err
	}
	return nil
}

func updateConstraints(isDetectMode bool, req admission.Request, results []shield.ResultFromRequestHandler) {
	for _, res := range results {
		if !res.Allow {
			errMsg := res.Message
			if isDetectMode {
				errMsg = "[Detection] " + res.Message
			}
			// update status
			_ = updateConstraintStatus(res.Profile, req, errMsg)

			log.WithFields(log.Fields{
				"namespace": req.Namespace,
				"name":      req.Name,
				"kind":      req.Kind.Kind,
				"operation": req.Operation,
			}).Debug("updated constraint status:", res.Profile)
		}
	}
}
