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
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	log "github.com/sirupsen/logrus"
	kubeutil "github.com/stolostron/integrity-shield/shield/pkg/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclient "k8s.io/client-go/kubernetes"
)

const k8sLogLevelEnvKey = "K8S_MANIFEST_SIGSTORE_LOG_LEVEL"
const defaultConfigKeyInConfigMap = "config.yaml"
const defaultPodNamespace = "integrity-shield-operator-system"
const defaultHandlerConfigMapName = "request-handler-config"

var logLevelMap = map[string]log.Level{
	"panic": log.PanicLevel,
	"fatal": log.FatalLevel,
	"error": log.ErrorLevel,
	"warn":  log.WarnLevel,
	"info":  log.InfoLevel,
	"debug": log.DebugLevel,
	"trace": log.TraceLevel,
}

type RequestHandlerConfig struct {
	KeyPathList             []string               `json:"keyPathList,omitempty"`
	RequestFilterProfile    RequestFilterProfile   `json:"requestFilterProfile,omitempty"`
	Log                     LogConfig              `json:"log,omitempty"`
	DecisionReporterConfig  DecisionReporterConfig `json:"decisionReporterConfig,omitempty"`
	SideEffectConfig        SideEffectConfig       `json:"sideEffect,omitempty"`
	DefaultConstraintAction Action                 `json:"defaultConstraintAction,omitempty"`
	Options                 []string
}

type LogConfig struct {
	Level                    string `json:"level,omitempty"`
	ManifestSigstoreLogLevel string `json:"manifestSigstoreLogLevel,omitempty"`
	Format                   string `json:"format,omitempty"`
}

type DecisionReporterConfig struct {
	Enabled   bool  `json:"enabled,omitempty"`
	LimitSize int64 `json:"limitSize,omitempty"`
	File      string
}

type SideEffectConfig struct {
	// Event
	CreateDenyEvent bool `json:"createDenyEvent"`
}

type RequestFilterProfile struct {
	SkipObjects  k8smanifest.ObjectReferenceList    `json:"skipObjects,omitempty"`
	SkipUsers    ObjectUserBindingList              `json:"skipUsers,omitempty"`
	IgnoreFields k8smanifest.ObjectFieldBindingList `json:"ignoreFields,omitempty"`
}

func SetupLogger(config LogConfig) {
	logLevelStr := config.Level
	k8sLogLevelStr := config.ManifestSigstoreLogLevel
	if logLevelStr == "" && k8sLogLevelStr == "" {
		logLevelStr = "info"
		k8sLogLevelStr = "info"
	}
	if logLevelStr == "" && k8sLogLevelStr != "" {
		logLevelStr = k8sLogLevelStr
	}
	if logLevelStr != "" && k8sLogLevelStr == "" {
		k8sLogLevelStr = logLevelStr
	}
	_ = os.Setenv(k8sLogLevelEnvKey, k8sLogLevelStr)
	logLevel, ok := logLevelMap[logLevelStr]
	if !ok {
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)
	// format
	if config.Format == "json" {
		log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})
	}
}

func LoadKeySecret(keySecretNamespace, keySecretName string) (string, error) {
	kubeconf, _ := kubeutil.GetKubeConfig()
	clientset, err := kubeclient.NewForConfig(kubeconf)
	if err != nil {
		return "", err
	}
	secret, err := clientset.CoreV1().Secrets(keySecretNamespace).Get(context.Background(), keySecretName, metav1.GetOptions{})
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed to get a secret `%s` in `%s` namespace", keySecretName, keySecretNamespace))
	}
	keyDir := fmt.Sprintf("/tmp/%s/%s/", keySecretNamespace, keySecretName)
	sumErr := []string{}
	keyPath := ""
	for fname, keyData := range secret.Data {
		err := os.MkdirAll(keyDir, os.ModePerm)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		fpath := filepath.Join(keyDir, fname)
		err = ioutil.WriteFile(fpath, keyData, 0644)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		keyPath = fpath
		break
	}
	if keyPath == "" && len(sumErr) > 0 {
		return "", errors.New(fmt.Sprintf("failed to save secret data as a file; %s", strings.Join(sumErr, "; ")))
	}
	if keyPath == "" {
		return "", errors.New(fmt.Sprintf("no key files are found in the secret `%s` in `%s` namespace", keySecretName, keySecretNamespace))
	}

	return keyPath, nil
}

func LoadRequestHandlerConfig() (*RequestHandlerConfig, error) {
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	configName := os.Getenv("REQUEST_HANDLER_CONFIG_NAME")
	if configName == "" {
		configName = defaultHandlerConfigMapName
	}
	configKey := os.Getenv("REQUEST_HANDLER_CONFIG_KEY")
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
	var sc *RequestHandlerConfig
	err = yaml.Unmarshal([]byte(cfgBytes), &sc)
	if err != nil {
		return sc, errors.Wrap(err, fmt.Sprintf("failed to unmarshal config.yaml into %T", sc))
	}
	return sc, nil
}
