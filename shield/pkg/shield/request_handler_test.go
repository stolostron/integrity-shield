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
	"io/ioutil"
	"testing"

	"github.com/ghodss/yaml"
	k8smnfconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	adreq1Path           = "./testdata/adreq_1.json"
	adreq2Path           = "./testdata/adreq_2.json"
	reqhandlerconfigPath = "./testdata/reqhandler_config.yaml"
)

func TestMutationCheck(t *testing.T) {
	testIgnoredFields := k8smanifest.ObjectFieldBindingList{
		k8smanifest.ObjectFieldBinding{
			Fields: []string{
				"data.key2",
			},
			Objects: k8smanifest.ObjectReferenceList{
				k8smanifest.ObjectReference{
					Kind: "ConfigMap",
					Name: "test-update-cm",
				},
				k8smanifest.ObjectReference{
					Kind: "ConfigMap",
					Name: "sample-cm",
				},
			},
		},
	}
	rhcBytes, err := ioutil.ReadFile(reqhandlerconfigPath)
	if err != nil {
		t.Error(err)
	}
	var rhc *k8smnfconfig.RequestHandlerConfig
	err = yaml.Unmarshal(rhcBytes, &rhc)
	if err != nil {
		t.Error(err)
		return
	}
	// no-mutation
	adreq1Bytes, err := ioutil.ReadFile(adreq1Path)
	if err != nil {
		t.Error(err)
	}
	var adreq1 *admission.Request
	err = json.Unmarshal(adreq1Bytes, &adreq1)
	if err != nil {
		t.Error(err)
		return
	}
	var resource unstructured.Unstructured
	objectBytes := adreq1.AdmissionRequest.Object.Raw
	err = json.Unmarshal(objectBytes, &resource)
	if err != nil {
		t.Error(err)
		return
	}
	ignoreFields := getMatchedIgnoreFields(testIgnoredFields, rhc.RequestFilterProfile.IgnoreFields, resource)
	res, err := mutationCheck(adreq1.OldObject.Raw, adreq1.Object.Raw, ignoreFields)
	if err != nil {
		t.Error(err)
		return
	}
	if res {
		t.Errorf("this test request should not have mutation: got: %v\nwant: %v", res, false)
		return
	}

	// mutation
	adreq2Bytes, err := ioutil.ReadFile(adreq2Path)
	if err != nil {
		t.Error(err)
	}
	var adreq2 *admission.Request
	err = json.Unmarshal(adreq2Bytes, &adreq2)
	if err != nil {
		t.Error(err)
		return
	}
	var resource2 unstructured.Unstructured
	object2Bytes := adreq2.AdmissionRequest.Object.Raw
	err = json.Unmarshal(object2Bytes, &resource2)
	if err != nil {
		t.Error(err)
		return
	}
	ignoreFields2 := getMatchedIgnoreFields(testIgnoredFields, rhc.RequestFilterProfile.IgnoreFields, resource2)
	res2, err := mutationCheck(adreq2.OldObject.Raw, adreq2.Object.Raw, ignoreFields2)
	if err != nil {
		t.Error(err)
		return
	}
	if !res2 {
		t.Errorf("this test has mutation: got: %v\nwant: %v", res, true)
		return
	}
}
