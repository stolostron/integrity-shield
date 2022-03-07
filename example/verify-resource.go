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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"

	"github.com/ghodss/yaml"
	"github.com/stolostron/integrity-shield/shield/pkg/config"
	"github.com/stolostron/integrity-shield/shield/pkg/shield"
	admission "k8s.io/api/admission/v1beta1"
)

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		fmt.Println("Please input admission request and verify rule")
		return
	}

	// Admission Request
	adreqPath, _ := filepath.Abs(args[0])
	adreqBytes, err := ioutil.ReadFile(adreqPath)
	if err != nil {
		fmt.Println(err)
		return
	}

	var adreq *admission.AdmissionRequest
	err = json.Unmarshal(adreqBytes, &adreq)
	if err != nil {
		fmt.Println(err)
		return
	}

	// ManifestVerifyRule
	rulePath, _ := filepath.Abs(args[1])
	ruleBytes, err := ioutil.ReadFile(rulePath)
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
