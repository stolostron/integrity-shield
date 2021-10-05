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
	apiv1 "github.com/IBM/integrity-enforcer/integrity-shield-operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// request handler config
func BuildReqConfigForIShield(cr *apiv1.IntegrityShield) *corev1.ConfigMap {
	data := map[string]string{
		cr.Spec.RequestHandlerConfigKey: cr.Spec.RequestHandlerConfig,
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.RequestHandlerConfigName,
			Namespace: cr.Namespace,
		},
		Data: data,
	}
	return cm
}

// request handler config
func BuildACConfigForIShield(cr *apiv1.IntegrityShield) *corev1.ConfigMap {
	data := map[string]string{
		cr.Spec.AdmissionControllerConfigKey: cr.Spec.AdmissionControllerConfig,
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.AdmissionControllerConfigName,
			Namespace: cr.Namespace,
		},
		Data: data,
	}
	return cm
}
