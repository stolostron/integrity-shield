//
// Copyright 2022 IBM Corporation
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
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/stolostron/integrity-shield/shield/pkg/config"
	admission "k8s.io/api/admission/v1beta1"
)

var (
	adreq_cm              = "./testdata/adreq_cm.json"
	adreq_cm_sig          = "./testdata/adreq_cm2.json"
	adreq_secret          = "./testdata/adreq_secret.json"
	adreq_secret_sig      = "./testdata/adreq_secret2.json"
	adreq_crd             = "./testdata/adreq_crd.json"
	adreq_crd_sig         = "./testdata/adreq_crd2.json"
	adreq_role            = "./testdata/adreq_role.json"
	adreq_role_sig        = "./testdata/adreq_role2.json"
	adreq_rb              = "./testdata/adreq_rolebinding.json"
	adreq_rb_sig          = "./testdata/adreq_rolebinding2.json"
	adreq_clusterrole     = "./testdata/adreq_clusterrole.json"
	adreq_clusterrole_sig = "./testdata/adreq_clusterrole2.json"
	adreq_crb             = "./testdata/adreq_clusterrolebinding.json"
	adreq_crb_sig         = "./testdata/adreq_clusterrolebinding2.json"
	adreq_deployment      = "./testdata/adreq_deployment.json"
	adreq_deployment_sig  = "./testdata/adreq_deployment2.json"
	adreq_sa              = "./testdata/adreq_sa.json"
	adreq_sa_sig          = "./testdata/adreq_sa2.json"
	adreq_svc             = "./testdata/adreq_service.json"
	adreq_svc_sig         = "./testdata/adreq_service2.json"
	rule                  = "./testdata/test_rule.yaml"
)

func TestVerifyResource(t *testing.T) {
	// ManifestVerifyRule
	rulePath, _ := filepath.Abs(rule)
	ruleBytes, _ := ioutil.ReadFile(rulePath)
	var rule *config.ManifestVerifyRule
	_ = yaml.Unmarshal(ruleBytes, &rule)

	// use integrity-shield-operator-system namespace for dry-run
	commonRule := config.NewManifestVerifyConfig("integrity-shield-operator-system")

	/*---- ConfigMap ----*/
	// invalid
	adreq := loadRequest(adreq_cm)
	allow, _, err := VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, false)
	}

	// valid
	adreq = loadRequest(adreq_cm_sig)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, true)
	}

	/*---- Secret ----*/
	// invalid
	adreq = loadRequest(adreq_secret)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, false)
	}

	// valid
	adreq = loadRequest(adreq_secret_sig)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, true)
	}

	/*---- CRD ----*/
	// invalid
	adreq = loadRequest(adreq_crd)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, false)
	}

	// valid
	adreq = loadRequest(adreq_crd_sig)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, true)
	}

	/*---- Role ----*/
	// invalid
	adreq = loadRequest(adreq_role)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, false)
	}

	// valid
	adreq = loadRequest(adreq_role_sig)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, true)
	}

	/*---- RoleBinding ----*/
	// invalid
	adreq = loadRequest(adreq_rb)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, false)
	}

	// valid
	adreq = loadRequest(adreq_rb_sig)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, true)
	}

	/*---- Deployment ----*/
	// invalid
	adreq = loadRequest(adreq_deployment)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, false)
	}

	// valid
	adreq = loadRequest(adreq_deployment_sig)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, true)
	}

	/*---- ClusterRole ----*/
	// invalid
	adreq = loadRequest(adreq_clusterrole)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, false)
	}

	// valid
	adreq = loadRequest(adreq_clusterrole_sig)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, true)
	}

	/*---- ClusterRoleBinding ----*/
	// invalid
	adreq = loadRequest(adreq_crb)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, false)
	}

	// valid
	adreq = loadRequest(adreq_crb_sig)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, true)
	}

	/*---- ServiceAccount ----*/
	// invalid
	adreq = loadRequest(adreq_sa)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, false)
	}

	// valid
	adreq = loadRequest(adreq_sa_sig)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, true)
	}

	/*---- Service ----*/
	// invalid
	adreq = loadRequest(adreq_svc)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, false)
	}

	// valid
	adreq = loadRequest(adreq_svc_sig)
	allow, _, err = VerifyResource(adreq, commonRule, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !allow {
		t.Errorf("this test request should not be verified: got: %v\nwant: %v", allow, true)
	}

	return
}

func loadRequest(file string) (adreq *admission.AdmissionRequest) {
	// Admission Request
	adreqPath, _ := filepath.Abs(file)
	adreqBytes, err := ioutil.ReadFile(adreqPath)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = json.Unmarshal(adreqBytes, &adreq)
	if err != nil {
		fmt.Println(err)
		return
	}
	return adreq
}
