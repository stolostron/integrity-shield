// Copyright 2021  IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	admv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	intstr "k8s.io/apimachinery/pkg/util/intstr"
)

const (
	DefaultIShieldWebhookTimeout = 10
	DefaultIShieldAPILabel       = "integrity-shield-api"

	CleanupFinalizerName = "cleanup.finalizers.integrityshield.io"
	CsvPath              = "./bundle/manifests/integrity-shield-operator.clusterserviceversion.yaml"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IntegrityShieldSpec defines the desired state of IntegrityShield
type IntegrityShieldSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	MaxSurge       *intstr.IntOrString `json:"maxSurge,omitempty"`
	MaxUnavailable *intstr.IntOrString `json:"maxUnavailable,omitempty"`
	ReplicaCount   *int32              `json:"replicaCount,omitempty"`
	MetaLabels     map[string]string   `json:"labels,omitempty"`
	NodeSelector   map[string]string   `json:"nodeSelector,omitempty"`
	Affinity       *v1.Affinity        `json:"affinity,omitempty"`
	Tolerations    []v1.Toleration     `json:"tolerations,omitempty"`

	Security SecurityConfig `json:"security,omitempty"`

	// request handler
	API                      APIContainer `json:"shieldApi,omitempty"`
	RequestHandlerConfigKey  string       `json:"requestHandlerConfigKey,omitempty"`
	RequestHandlerConfigName string       `json:"requestHandlerConfigName,omitempty"`
	RequestHandlerConfig     string       `json:"requestHandlerConfig,omitempty"`
	ApiServiceName           string       `json:"shieldApiServiceName,omitempty"`
	ApiServicePort           int32        `json:"shieldApiServicePort,omitempty"`

	// admission controller
	ControllerContainer           ControllerContainer `json:"admissionController,omitempty"`
	AdmissionControllerConfigKey  string              `json:"admissionControllerConfigKey,omitempty"`
	AdmissionControllerConfigName string              `json:"admissionControllerConfigName,omitempty"`
	AdmissionControllerConfig     string              `json:"admissionControllerConfig,omitempty"`

	// observer
	Observer Observer `json:"observer,omitempty"`

	APITlsSecretName           string     `json:"shieldApiTlsSecretName,omitempty"`
	WebhookServerTlsSecretName string     `json:"webhookServerTlsSecretName,omitempty"`
	WebhookServiceName         string     `json:"webhookServiceName,omitempty"`
	WebhookConfigName          string     `json:"webhookConfigName,omitempty"`
	WebhookNamespacedResource  admv1.Rule `json:"webhookNamespacedResource,omitempty"`
	WebhookClusterResource     admv1.Rule `json:"webhookClusterResource,omitempty"`

	// gatekeeper
	UseGatekeeper bool   `json:"useGatekeeper,omitempty"`
	Rego          string `json:"rego,omitempty"`
}

type APIContainer struct {
	Name            string                  `json:"name,omitempty"`
	SelectorLabels  map[string]string       `json:"selector,omitempty"`
	SecurityContext *v1.SecurityContext     `json:"securityContext,omitempty"`
	ImagePullPolicy v1.PullPolicy           `json:"imagePullPolicy,omitempty"`
	Image           string                  `json:"image,omitempty"`
	Tag             string                  `json:"imageTag,omitempty"`
	Port            int32                   `json:"port,omitempty"`
	Resources       v1.ResourceRequirements `json:"resources,omitempty"`
}

type ControllerContainer struct {
	Name            string                  `json:"name,omitempty"`
	SelectorLabels  map[string]string       `json:"selector,omitempty"`
	SecurityContext *v1.SecurityContext     `json:"securityContext,omitempty"`
	ImagePullPolicy v1.PullPolicy           `json:"imagePullPolicy,omitempty"`
	Image           string                  `json:"image,omitempty"`
	Tag             string                  `json:"imageTag,omitempty"`
	Port            int32                   `json:"port,omitempty"`
	Resources       v1.ResourceRequirements `json:"resources,omitempty"`
	Log             LogConfig               `json:"log,omitempty"`
}

type SecurityConfig struct {
	APIServiceAccountName      string                 `json:"serviceAccountName,omitempty"`
	ObserverServiceAccountName string                 `json:"observerServiceAccountName,omitempty"`
	ObserverRole               string                 `json:"observerRole,omitempty"`
	ObserverRoleBinding        string                 `json:"observerRoleBinding,omitempty"`
	APIRole                    string                 `json:"role,omitempty"`
	APIRoleBinding             string                 `json:"roleBinding,omitempty"`
	PodSecurityPolicyName      string                 `json:"podSecurityPolicyName,omitempty"`
	PodSecurityContext         *v1.PodSecurityContext `json:"securityContext,omitempty"`
	// AutoIShieldAdminCreationDisabled bool                   `json:"autoIShieldAdminRoleCreationDisabled,omitempty"`
}

type LogConfig struct {
	LogLevel  string `json:"level,omitempty"`
	LogFormat string `json:"format,omitempty"`
}

type Observer struct {
	Enabled                bool                    `json:"enabled,omitempty"`
	Name                   string                  `json:"name,omitempty"`
	SelectorLabels         map[string]string       `json:"selector,omitempty"`
	ImagePullPolicy        v1.PullPolicy           `json:"imagePullPolicy,omitempty"`
	Image                  string                  `json:"image,omitempty"`
	Tag                    string                  `json:"imageTag,omitempty"`
	SecurityContext        *v1.SecurityContext     `json:"securityContext,omitempty"`
	LogLevel               string                  `json:"logLevel,omitempty"`
	Interval               string                  `json:"interval,omitempty"`
	ExportDetailResult     bool                    `json:"exportDetailResult,omitempty"`
	ResultDetailConfigName string                  `json:"resultDetailConfigName,omitempty"`
	ResultDetailConfigKey  string                  `json:"resultDetailConfigKey,omitempty"`
	Resources              v1.ResourceRequirements `json:"resources,omitempty"`
}

// IntegrityShieldStatus defines the observed state of IntegrityShield
type IntegrityShieldStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// IntegrityShield is the Schema for the integrityshields API
type IntegrityShield struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IntegrityShieldSpec   `json:"spec,omitempty"`
	Status IntegrityShieldStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IntegrityShieldList contains a list of IntegrityShield
type IntegrityShieldList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IntegrityShield `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IntegrityShield{}, &IntegrityShieldList{})
}
