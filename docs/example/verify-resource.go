package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/ghodss/yaml"
	"github.com/stolostron/integrity-shield/shield/pkg/config"
	"github.com/stolostron/integrity-shield/shield/pkg/shield"
	admission "k8s.io/api/admission/v1beta1"
)

func main() {
	adreqBytes, err := ioutil.ReadFile("sample-request.json")
	if err != nil {
		fmt.Println(err)
		return
	}

	// Admission Request
	var adreq *admission.AdmissionRequest
	err = json.Unmarshal(adreqBytes, &adreq)
	if err != nil {
		fmt.Println(err)
		return
	}

	// ManifestVerifyRule
	ruleBytes, err := ioutil.ReadFile("sample-rule.yml")
	if err != nil {
		fmt.Println(err)
		return
	}

	var rule *config.ManifestVerifyRule
	err = yaml.Unmarshal(ruleBytes, &rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	// ManifestVerifyConfig
	// get default manifestVerifyConfig, use "default" namespace for dry-run.
	commonRule := config.NewManifestVerifyConfig("default")

	allow, msg, err := shield.VerifyResource(adreq, commonRule, rule) // verifyResource accepts (adreq, nil, rule)
	if err != nil {
		fmt.Println(err)
		return
	}
	res := fmt.Sprintf("[VerifyResource Result] allow: %s, reaseon: %s", strconv.FormatBool(allow), msg)
	fmt.Println(res)
	return
}
