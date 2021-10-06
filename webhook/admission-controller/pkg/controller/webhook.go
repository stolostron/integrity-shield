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

package controller

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/open-cluster-management/integrity-shield/shield/pkg/shield"
	acconfig "github.com/open-cluster-management/integrity-shield/webhook/admission-controller/pkg/config"
	"github.com/pkg/errors"
	cosign "github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclient "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const defaultConfigKeyInConfigMap = "config.yaml"
const defaultPodNamespace = "k8s-manifest-sigstore"
const defaultControllerConfigName = "admission-controller-config"
const logLevelEnvKey = "LOG_LEVEL"

var logLevelMap = map[string]log.Level{
	"panic": log.PanicLevel,
	"fatal": log.FatalLevel,
	"error": log.ErrorLevel,
	"warn":  log.WarnLevel,
	"info":  log.InfoLevel,
	"debug": log.DebugLevel,
	"trace": log.TraceLevel,
}

type AccumulatedResult struct {
	Allow   bool
	Message string
}

func init() {
	if os.Getenv("LOG_FORMAT") == "json" {
		log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})
	}
	logLevelStr := os.Getenv(logLevelEnvKey)
	if logLevelStr == "" {
		logLevelStr = "info"
	}
	logLevel, ok := logLevelMap[logLevelStr]
	if !ok {
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)
	cmd := cosign.Init()
	cmd.Exec(context.Background(), []string{})
	log.Info("initialized cosign.")
}

func ProcessRequest(req admission.Request) admission.Response {
	// load ac2 config
	config, err := loadAdmissionControllerConfig()
	if err != nil {
		log.Errorf("failed to load admission controller config; %s", err.Error())
		return admission.Allowed("error but allow for development")
	}

	// isScope check
	inScopeNamespace := config.InScopeNamespaceSelector.Match(req.Namespace)
	if !inScopeNamespace {
		return admission.Allowed("this namespace is out of scope")
	}
	// allow check
	allowedRequest := config.Allow.Match(req.Kind)
	if allowedRequest {
		return admission.Allowed("this kind is out of scope")
	}

	// load constraints
	constraints, err := LoadConstraints()
	if err != nil {
		log.Errorf("failed to load constratints; %s", err.Error())
		return admission.Allowed("error but allow for development")
	}

	results := []shield.ResultFromRequestHandler{}

	for _, constraint := range constraints {

		//match check: kind, namespace, label
		isMatched := matchCheck(req, constraint.Spec.Match)
		if !isMatched {
			r := shield.ResultFromRequestHandler{
				Allow:   true,
				Message: "not protected",
				Profile: constraint.Name,
			}
			results = append(results, r)
			continue
		}

		// pick parameters from constaint
		paramObj := GetParametersFromConstraint(constraint.Spec)

		// call request handler & receive result from request handler (allow, message)
		r := shield.RequestHandler(req, paramObj)

		r.Profile = constraint.Name
		results = append(results, *r)
	}

	// accumulate results from constraints
	ar := getAccumulatedResult(results)

	// mode check
	isDetectMode := acconfig.CheckIfDetectOnly(config.Mode)
	if !ar.Allow && isDetectMode {
		ar.Allow = true
		msg := "allowed by detection mode: " + ar.Message
		ar.Message = msg
	}

	// update status
	if config.SideEffect.UpdateMIPStatusForDeniedRequest {
		updateConstraints(isDetectMode, req, results)
	}

	// log
	log.WithFields(log.Fields{
		"namespace": req.Namespace,
		"name":      req.Name,
		"kind":      req.Kind.Kind,
		"operation": req.Operation,
		"allow":     ar.Allow,
	}).Info(ar.Message)

	// return admission response
	if ar.Allow {
		return admission.Allowed(ar.Message)
	} else {
		return admission.Denied(ar.Message)
	}
}

func loadAdmissionControllerConfig() (*acconfig.AdmissionControllerConfig, error) {
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	configName := os.Getenv("CONTROLLER_CONFIG_NAME")
	if configName == "" {
		configName = defaultControllerConfigName
	}
	configKey := os.Getenv("CONTROLLER_CONFIG_KEY")
	if configKey == "" {
		configKey = defaultConfigKeyInConfigMap
	}
	// load
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, nil
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil, nil
	}
	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), configName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("failed to get a configmap `%s` in `%s` namespace", configName, namespace))
	}

	cfgBytes, found := cm.Data[configKey]
	if !found {
		return nil, errors.New(fmt.Sprintf("`%s` is not found in configmap", configKey))
	}
	var sc *acconfig.AdmissionControllerConfig
	err = yaml.Unmarshal([]byte(cfgBytes), &sc)
	if err != nil {
		return sc, errors.Wrap(err, fmt.Sprintf("failed to unmarshal config.yaml into %T", sc))
	}
	return sc, nil
}

func getAccumulatedResult(results []shield.ResultFromRequestHandler) *AccumulatedResult {
	denyMessages := []string{}
	allowMessages := []string{}
	accumulatedRes := &AccumulatedResult{}
	for _, result := range results {
		if !result.Allow {
			msg := "[" + result.Profile + "]" + result.Message
			denyMessages = append(denyMessages, msg)
		} else {
			msg := "[" + result.Profile + "]" + result.Message
			allowMessages = append(allowMessages, msg)
		}
	}
	if len(denyMessages) != 0 {
		accumulatedRes.Allow = false
		accumulatedRes.Message = strings.Join(denyMessages, ";")
		return accumulatedRes
	}
	accumulatedRes.Allow = true
	accumulatedRes.Message = strings.Join(allowMessages, ";")
	return accumulatedRes
}
