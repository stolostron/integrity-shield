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
	"strings"

	apiv1 "github.com/stolostron/integrity-shield/integrity-shield-operator/api/v1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// request handler config
func BuildConstraintTemplateForIShield(cr *apiv1.IntegrityShield) *v1beta1.ConstraintTemplate {
	trueVar := true
	crd := v1beta1.CRD{
		Spec: v1beta1.CRDSpec{
			Names: v1beta1.Names{
				Kind: "ManifestIntegrityConstraint",
			},
			Validation: &v1beta1.Validation{
				OpenAPIV3Schema: &extv1.JSONSchemaProps{
					XPreserveUnknownFields: &trueVar,
				},
			},
		},
	}
	rego := strings.Replace(cr.Spec.Rego, "REPLACE_WITH_SERVER_NAMESPSCE", cr.Namespace, 1)
	targets := []v1beta1.Target{
		{
			Target: "admission.k8s.gatekeeper.sh",
			Rego:   rego,
		},
	}
	template := &v1beta1.ConstraintTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "manifestintegrityconstraint",
			Namespace: cr.Namespace,
		},
		Spec: v1beta1.ConstraintTemplateSpec{
			CRD:     crd,
			Targets: targets,
		},
	}
	return template
}
