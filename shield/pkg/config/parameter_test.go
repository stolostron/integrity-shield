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

package config

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	adreqPath = "./testdata/adreq_0.json"
)

func TestImageProfile(t *testing.T) {
	imgProfile := ImageProfile{
		Match: ImageRefList{
			ImageRef("sample-registry/test-match-*"),
		},
		Exclude: ImageRefList{
			ImageRef("sample-registry/test-exclude-*"),
		},
	}

	if !imgProfile.Enabled() {
		t.Errorf("imageProfile is not enabled: got: %v\nwant: %v", imgProfile.Enabled(), true)
		return
	}

	testImage1 := "sample-registry/test-match-image:0.0.1"
	testImage2 := "sample-registry/test-exclude-image:0.0.2"
	expect1 := true
	expect2 := false

	res1 := imgProfile.MatchWith(testImage1)
	res2 := imgProfile.MatchWith(testImage2)

	if res1 != expect1 {
		t.Errorf("image does not match: got: %v\nwant: %v", res1, expect1)
		return
	}

	if res2 != expect2 {
		t.Errorf("image should be excluded: got: %v\nwant: %v", res2, expect2)
		return
	}
}

func TestManifestIntegrityConstraint(t *testing.T) {
	adreqBytes, err := ioutil.ReadFile(adreqPath)
	if err != nil {
		t.Error(err)
	}

	var adreq *admission.Request
	err = json.Unmarshal(adreqBytes, &adreq)
	if err != nil {
		t.Error(err)
		return
	}
	var resource unstructured.Unstructured
	objectBytes := adreq.AdmissionRequest.Object.Raw
	err = json.Unmarshal(objectBytes, &resource)
	if err != nil {
		t.Error(err)
		return
	}
	testParam1 := ManifestIntegrityConstraint{
		SkipUsers: ObjectUserBindingList{
			{
				Users: []string{
					"kubernetes-admin",
				},
				Objects: []k8smanifest.ObjectReference{
					{
						Kind: "ConfigMap",
						Name: "sample-cm",
					},
				},
			},
		},
	}
	testParam2 := ManifestIntegrityConstraint{
		InScopeUsers: ObjectUserBindingList{
			{
				Users: []string{
					"kubernetes-admin",
				},
			},
		},
	}
	res := testParam1.SkipUsers.Match(resource, adreq.UserInfo.Username)
	res2 := testParam2.InScopeUsers.Match(resource, adreq.UserInfo.Username)

	if res != true {
		t.Errorf("this test request should match SkipUsers: got: %v\nwant: %v", res, true)
		return
	}
	if res2 != true {
		t.Errorf("this test request should match InScopeUsers: got: %v\nwant: %v", res, true)
		return
	}

}
