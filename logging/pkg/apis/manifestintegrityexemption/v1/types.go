//
// Copyright 2021 IBM Corporation
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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ManifestIntegrityExemptionSpec defines the desired state of AppEnforcePolicy
type ManifestIntegrityExemptionSpec struct {
	ConstraintName   string            `json:"constraintName"`
	AdmissionResults []AdmissionResult `json:"admissionResults"`
	LastUpdate       string            `json:"lastUpdate"`
}

// {"userInfo":{"username":"kubernetes-admin","groups":["system:masters","system:authenticated"]}}
type AdmissionResult struct {
	Allow          bool   `json:"allow,omitempty"`
	ApiGroup       string `json:"apiGroup,omitempty"`
	ApiVersion     string `json:"apiVersion,omitempty"`
	Kind           string `json:"kind,omitempty"`
	Resource       string `json:"resource,omitempty"`
	Name           string `json:"name,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	Reason         string `json:"reason,omitempty"`
	UserName       string `json:"userName,omitempty"`
	AdmissionTime  string `json:"admissionTime,omitempty"`
	ConstraintName string `json:"constraintName"`
}

// ManifestIntegrityExemptionStatus defines the observed state of ManifestIntegrityExemption
type ManifestIntegrityExemptionStatus struct {
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=manifestintegrityexemption,scope=Namespaced

// EnforcePolicy is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ManifestIntegrityState is the CRD. Use this command to generate deepcopy for it:
type ManifestIntegrityExemption struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ManifestIntegrityExemptionSpec   `json:"spec,omitempty"`
	Status ManifestIntegrityExemptionStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ManifestIntegrityStateList contains a list of ManifestIntegrityState
type ManifestIntegrityExemptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ManifestIntegrityExemption `json:"items"`
}
