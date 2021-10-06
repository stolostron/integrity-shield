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

package resources

import (
	"fmt"

	apiv1 "github.com/open-cluster-management/integrity-shield/integrity-shield-operator/api/v1"
	admregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	intstr "k8s.io/apimachinery/pkg/util/intstr"
)

// webhook service
func BuildServiceForIShield(cr *apiv1.IntegrityShield) *corev1.Service {
	var targetport intstr.IntOrString
	targetport.Type = intstr.String
	targetport.StrVal = "validator-port"
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.WebhookServiceName,
			Namespace: cr.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       443,
					TargetPort: targetport,
				},
			},
			Selector: cr.Spec.ControllerContainer.SelectorLabels,
		},
	}
	return svc
}

// api service
func BuildAPIServiceForIShield(cr *apiv1.IntegrityShield) *corev1.Service {
	var targetport intstr.IntOrString
	targetport.Type = intstr.String
	targetport.StrVal = "ishield-api"
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.ApiServiceName,
			Namespace: cr.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       cr.Spec.ApiServicePort,
					TargetPort: targetport, //"ishield-api"
				},
			},
			Selector: cr.Spec.API.SelectorLabels,
		},
	}
	return svc
}

//webhook configuration
func BuildValidatingWebhookConfigurationForIShield(cr *apiv1.IntegrityShield) *admregv1.ValidatingWebhookConfiguration {

	namespaced := admregv1.NamespacedScope
	cluster := admregv1.ClusterScope

	namespacedRule := cr.Spec.WebhookNamespacedResource
	namespacedRule.Scope = &namespaced

	clusterRule := cr.Spec.WebhookClusterResource
	clusterRule.Scope = &cluster

	var path *string
	validate := "/validate-resource"
	path = &validate

	var empty []byte

	sideEffect := admregv1.SideEffectClassNoneOnDryRun
	timeoutSeconds := int32(apiv1.DefaultIShieldWebhookTimeout)

	rules := []admregv1.RuleWithOperations{
		{
			Operations: []admregv1.OperationType{
				admregv1.Create, admregv1.Update,
			},
			Rule: namespacedRule,
		},
		{
			Operations: []admregv1.OperationType{
				admregv1.Create, admregv1.Update,
			},
			Rule: clusterRule,
		},
	}

	wc := &admregv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.WebhookConfigName,
			Namespace: cr.Namespace,
		},
		Webhooks: []admregv1.ValidatingWebhook{
			{
				Name: fmt.Sprintf("ac-server.%s.svc", cr.Namespace),
				ClientConfig: admregv1.WebhookClientConfig{
					Service: &admregv1.ServiceReference{
						Name:      cr.Spec.WebhookServiceName,
						Namespace: cr.Namespace,
						Path:      path,
					},
					CABundle: empty,
				},
				Rules:                   rules,
				SideEffects:             &sideEffect,
				TimeoutSeconds:          &timeoutSeconds,
				AdmissionReviewVersions: []string{"v1beta1"},
			},
		},
	}
	return wc
}
