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
	apiv1 "github.com/open-cluster-management/integrity-shield/integrity-shield-operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ishield-api-tls
func BuildTlsSecretForIShield(cr *apiv1.IntegrityShield) *corev1.Secret {
	var empty []byte
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.APITlsSecretName,
			Namespace: cr.Namespace,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       empty, // "tls.crt"
			corev1.TLSPrivateKeyKey: empty,
			"ca.crt":                empty,
		},
		Type: corev1.SecretTypeTLS,
	}
	return sec
}

// ishield-webhook-tls
func BuildAPITlsSecretForIShield(cr *apiv1.IntegrityShield) *corev1.Secret {
	var empty []byte
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.WebhookServerTlsSecretName,
			Namespace: cr.Namespace,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       empty, // "tls.crt"
			corev1.TLSPrivateKeyKey: empty,
			"ca.crt":                empty,
		},
		Type: corev1.SecretTypeTLS,
	}
	return sec
}
