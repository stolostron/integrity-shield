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

package verifier

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"strconv"
	"strings"
	"testing"

	rspapi "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	"github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	logger "github.com/IBM/integrity-enforcer/verifier/pkg/util/logger"
	"github.com/IBM/integrity-enforcer/verifier/pkg/verifier/config"
)

const (
	testReqcFile   = "testdata/reqc_NUM.json"
	testConfigFile = "testdata/config_NUM.json"
	testDataFile   = "testdata/data_NUM.json"
	testCtxFile    = "testdata/ctx_NUM.json"
	//testDrFile     = "testdata/dr.json"
	testProfFile = "testdata/prof_NUM.json"
	testDrFile   = "testdata/dr_NUM.json"
)

const MaxCaseNum = 2

func TestHandlerCheck(t *testing.T) {
	for i := 0; i < MaxCaseNum; i++ {
		testInScopeCheck(t, i)
		testFormatCheck(t, i)
		testIVResourceCheck(t, i)
		testDeleteCheck(t, i)
		testProtectedCheck(t, i)
		testRSPCheck(t, i)
	}
}

func init() {
	var config *config.VerifierConfig
	configBytes, _ := ioutil.ReadFile(testFileName(testConfigFile, 0))
	_ = json.Unmarshal(configBytes, &config)
	logger.InitContextLogger(config.ContextLoggerConfig())
	logger.InitServerLogger(config.LoggerConfig())
}

func testFileName(fname string, num int) string {
	return strings.Replace(fname, "NUM", strconv.Itoa(num), 1)
}

func getTestData(num int) (*common.ReqContext, *config.VerifierConfig, *RunData, *CheckContext, *DecisionResult, rspapi.ResourceSigningProfile, *DecisionResult) {

	var reqc *common.ReqContext
	var config *config.VerifierConfig
	var data *RunData
	var ctx *CheckContext
	var dr0 *DecisionResult
	var prof rspapi.ResourceSigningProfile
	var dr *DecisionResult

	reqcBytes, _ := ioutil.ReadFile(testFileName(testReqcFile, num))
	configBytes, _ := ioutil.ReadFile(testFileName(testConfigFile, num))
	dataBytes, _ := ioutil.ReadFile(testFileName(testDataFile, num))
	ctxBytes, _ := ioutil.ReadFile(testFileName(testCtxFile, num))
	//drBytes, _ := ioutil.ReadFile(testDrFile)
	profBytes, _ := ioutil.ReadFile(testFileName(testProfFile, num))
	drBytes, _ := ioutil.ReadFile(testFileName(testDrFile, num))
	_ = json.Unmarshal(reqcBytes, &reqc)
	_ = json.Unmarshal(configBytes, &config)
	_ = json.Unmarshal(dataBytes, &data)
	_ = json.Unmarshal(ctxBytes, &ctx)
	//_ = json.Unmarshal(drBytes, &dr)
	_ = json.Unmarshal(profBytes, &prof)
	_ = json.Unmarshal(drBytes, &dr)
	dr0 = &DecisionResult{
		Type: common.DecisionUndetermined,
	}
	return reqc, config, data, ctx, dr0, prof, dr
}

func testInScopeCheck(t *testing.T, caseNum int) {
	reqc, config, data, ctx, expectedDr, _, _ := getTestData(caseNum)
	actualDr := inScopeCheck(reqc, config, data, ctx)

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("[Case %s] Test failed for inScopeCheck()\nexpected:\n  %s\nactual:\n  %s", strconv.Itoa(caseNum), string(actDrBytes), string(expDrBytes))
	} else {
		t.Logf("[Case %s] Test for inScopeCheck() passed.", strconv.Itoa(caseNum))
	}
}

func testFormatCheck(t *testing.T, caseNum int) {
	reqc, config, data, ctx, expectedDr, _, _ := getTestData(caseNum)
	actualDr := formatCheck(reqc, config, data, ctx)

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("[Case %s] Test failed for formatCheck()\nexpected:\n  %s\nactual\n  %s", strconv.Itoa(caseNum), string(actDrBytes), string(expDrBytes))
	} else {
		t.Logf("[Case %s] Test for formatCheck() passed.", strconv.Itoa(caseNum))
	}
}

func testIVResourceCheck(t *testing.T, caseNum int) {
	reqc, config, data, ctx, expectedDr, _, _ := getTestData(caseNum)
	actualDr := ivResourceCheck(reqc, config, data, ctx)

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("[Case %s] Test failed for ivResourceCheck()\nexpected:\n  %s\nactual:\n  %s", strconv.Itoa(caseNum), string(actDrBytes), string(expDrBytes))
	} else {
		t.Logf("[Case %s] Test for ivResourceCheck() passed.", strconv.Itoa(caseNum))
	}
}

func testDeleteCheck(t *testing.T, caseNum int) {
	reqc, config, data, ctx, expectedDr, _, _ := getTestData(caseNum)
	actualDr := deleteCheck(reqc, config, data, ctx)

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("[Case %s] Test failed for deleteCheck()\nexpected:\n  %s\nactual:\n  %s", strconv.Itoa(caseNum), string(actDrBytes), string(expDrBytes))
	} else {
		t.Logf("[Case %s] Test for deleteCheck() passed.", strconv.Itoa(caseNum))
	}
}

func testProtectedCheck(t *testing.T, caseNum int) {
	reqc, config, data, ctx, expectedDr, expectedMatchedProf, _ := getTestData(caseNum)
	actualDr, actualMatchedProfiles := protectedCheck(reqc, config, data, ctx)

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("[Case %s] Test failed for protectedCheck()\nexpected:\n  %s\nactual:\n  %s", strconv.Itoa(caseNum), string(actDrBytes), string(expDrBytes))
	}
	if len(actualMatchedProfiles) != 1 || !reflect.DeepEqual(actualMatchedProfiles[0], expectedMatchedProf) {
		actProfBytes, _ := json.Marshal(actualMatchedProfiles[0])
		expProfBytes, _ := json.Marshal(expectedMatchedProf)
		t.Errorf("[Case %s] Test failed for protectedCheck()\nexpected :\n  %s\nactual:\n  %s", strconv.Itoa(caseNum), string(actProfBytes), string(expProfBytes))
	} else {
		t.Logf("[Case %s] Test for protectedCheck() passed.", strconv.Itoa(caseNum))
	}
}

func testRSPCheck(t *testing.T, caseNum int) {
	reqc, config, data, ctx, _, prof, expectedDr := getTestData(caseNum)
	actualDr := resourceSigningProfileCheck(prof, reqc, config, data, ctx)
	actualDr.denyRSP = nil // `denyRSP` is an unexported field. this must be ignored when checking equivalent

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("[Case %s] Test failed for resourceSigningProfileCheck()\nexpected:\n  %s\nactual:\n  %s", strconv.Itoa(caseNum), string(actDrBytes), string(expDrBytes))
	} else {
		t.Logf("[Case %s] Test for resourceSigningProfileCheck() passed.", strconv.Itoa(caseNum))
	}
}
