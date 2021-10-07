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

package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	vrc "github.com/IBM/integrity-enforcer/observer/pkg/apis/manifestintegritystate/v1"
	vrcclient "github.com/IBM/integrity-enforcer/observer/pkg/client/manifestintegritystate/clientset/versioned/typed/manifestintegritystate/v1"
	k8smnfconfig "github.com/IBM/integrity-enforcer/shield/pkg/config"
	"github.com/pkg/errors"
	cosign "github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const timeFormat = "2006-01-02 15:04:05"

const exportDetailResult = "ENABLE_DETAIL_RESULT"
const detailResultConfigName = "OBSERVER_RESULT_CONFIG_NAME"
const detailResultConfigKey = "OBSERVER_RESULT_CONFIG_KEY"

const defaultKeyInConfigMap = "config.yaml"
const defaultPodNamespace = "integrity-shield-operator-system"
const defaultExportDetailResult = true
const defaultObserverResultDetailConfigName = "verify-result-detail"

const logLevelEnvKey = "LOG_LEVEL"
const k8sLogLevelEnvKey = "K8S_MANIFEST_SIGSTORE_LOG_LEVEL"

// const ImageRefAnnotationKey = "cosign.sigstore.dev/imageRef"

const VerifyResourceViolationLabel = "integrityshield.io/verifyResourceViolation"
const VerifyResourceIgnoreLabel = "integrityshield.io/verifyResourceIgnored"

const rekorServerEnvKey = "REKOR_SERVER"

type Observer struct {
	APIResources []groupResource

	dynamicClient dynamic.Interface
}

// Observer Result Detail
type VerifyResultDetail struct {
	Time                 string                            `json:"time"`
	Namespace            string                            `json:"namespace"`
	Name                 string                            `json:"name"`
	Kind                 string                            `json:"kind"`
	ApiGroup             string                            `json:"apiGroup"`
	ApiVersion           string                            `json:"apiVersion"`
	Error                bool                              `json:"error"`
	Message              string                            `json:"message"`
	Violation            bool                              `json:"violation"`
	VerifyResourceResult *k8smanifest.VerifyResourceResult `json:"verifyResourceResult"`
}
type ConstraintResult struct {
	ConstraintName  string               `json:"constraintName"`
	Violation       bool                 `json:"violation"`
	TotalViolations int                  `json:"totalViolations"`
	Results         []VerifyResultDetail `json:"results"`
	Constraint      ConstraintSpec       `json:"constraint"`
}

type ObservationDetailResults struct {
	Time              string             `json:"time"`
	ConstraintResults []ConstraintResult `json:"constraintResults"`
}

// groupResource contains the APIGroup and APIResource
type groupResource struct {
	APIGroup    string             `json:"apiGroup"`
	APIVersion  string             `json:"apiVersion"`
	APIResource metav1.APIResource `json:"resource"`
}

type groupResourceWithTargetNS struct {
	groupResource    `json:""`
	TargetNamespaces []string `json:"targetNamespace"`
}

var logLevelMap = map[string]log.Level{
	"panic": log.PanicLevel,
	"fatal": log.FatalLevel,
	"error": log.ErrorLevel,
	"warn":  log.WarnLevel,
	"info":  log.InfoLevel,
	"debug": log.DebugLevel,
	"trace": log.TraceLevel,
}

func NewObserver() *Observer {
	insp := &Observer{}
	return insp
}

func (self *Observer) Init() error {
	log.Info("initialize observer.")
	kubeconf, _ := kubeutil.GetKubeConfig()

	var err error

	err = self.getAPIResources(kubeconf)
	if err != nil {
		return err
	}

	dynamicClient, err := dynamic.NewForConfig(kubeconf)
	if err != nil {
		return err
	}
	self.dynamicClient = dynamicClient

	// log
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
	os.Setenv(k8sLogLevelEnvKey, logLevelStr)
	log.SetLevel(logLevel)

	log.Info("initialize cosign.")
	cmd := cosign.Init()
	_ = cmd.Exec(context.Background(), []string{})

	return nil
}

func (self *Observer) Run() {
	// load config -> requestHandlerConfig
	rhconfig, err := k8smnfconfig.LoadRequestHandlerConfig()
	if err != nil {
		log.Error("Failed to load RequestHandlerConfig; err: ", err.Error())
	}

	// load constraints
	constraints, err := self.loadConstraints()
	if err != nil {
		if err.Error() == "the server could not find the requested resource" {
			log.Info("no observation results")
			return
		} else {
			log.Error("Failed to load constraints; err: ", err.Error())
		}
	}

	// setup env value for sigstore
	if rhconfig.SigStoreConfig.RekorServer != "" {
		_ = os.Setenv(rekorServerEnvKey, rhconfig.SigStoreConfig.RekorServer)
		debug := os.Getenv(rekorServerEnvKey)
		log.Debug("REKOR_SERVER is set as ", debug)
	} else {
		_ = os.Setenv(rekorServerEnvKey, "")
		debug := os.Getenv(rekorServerEnvKey)
		log.Debug("REKOR_SERVER is set as ", debug)
	}

	// ObservationDetailResults
	var constraintResults []ConstraintResult
	for _, constraint := range constraints {
		constraintName := constraint.Parameters.ConstraintName
		var violations []vrc.VerifyResult
		var nonViolations []vrc.VerifyResult
		narrowedGVKList := self.getPossibleProtectedGVKs(constraint.Match)
		if narrowedGVKList == nil {
			log.Info("there is no resources to observe in the constraint:", constraint.Parameters.ConstraintName)
			return
		}
		// get all resources of extracted GVKs
		resources := []unstructured.Unstructured{}
		for _, gResource := range narrowedGVKList {
			tmpResources, _ := self.getAllResoucesByGroupResource(gResource)
			resources = append(resources, tmpResources...)
		}

		// check all resources by verifyResource
		ignoreFields := constraint.Parameters.IgnoreFields
		secrets := constraint.Parameters.KeyConfigs
		ignoreFields = append(ignoreFields, rhconfig.RequestFilterProfile.IgnoreFields...)
		skipObjects := rhconfig.RequestFilterProfile.SkipObjects
		skipObjects = append(skipObjects, constraint.Parameters.SkipObjects...)
		results := []VerifyResultDetail{}
		for _, resource := range resources {
			// skip object
			result := ObserveResource(resource, constraint.Parameters.SignatureRef, ignoreFields, skipObjects, secrets)
			imgAllow, imgMsg := ObserveImage(resource, constraint.Parameters.ImageProfile)
			if !imgAllow {
				if !result.Violation {
					result.Violation = true
					result.Message = imgMsg
				} else {
					result.Message = fmt.Sprintf("%s, [Image]%s", result.Message, imgMsg)
				}
			}

			log.Debug("VerifyResultDetail", result)
			results = append(results, result)
		}

		// prepare for manifest integrity state
		for _, res := range results {
			// simple result
			if res.Violation {
				vres := vrc.VerifyResult{
					Namespace:  res.Namespace,
					Name:       res.Name,
					Kind:       res.Kind,
					ApiGroup:   res.ApiGroup,
					ApiVersion: res.ApiVersion,
					Result:     res.Message,
				}
				violations = append(violations, vres)
			} else {
				vres := vrc.VerifyResult{
					Namespace:  res.Namespace,
					Name:       res.Name,
					Kind:       res.Kind,
					ApiGroup:   res.ApiGroup,
					ApiVersion: res.ApiVersion,
					Signer:     res.VerifyResourceResult.Signer,
					SigRef:     res.VerifyResourceResult.SigRef,
					SignedTime: res.VerifyResourceResult.SignedTime,
					Result:     res.Message,
				}
				nonViolations = append(nonViolations, vres)
			}
			log.WithFields(log.Fields{
				"constraintName": constraintName,
				"violation":      res.Violation,
				"kind":           res.Kind,
				"name":           res.Name,
				"namespace":      res.Namespace,
			}).Info(res.Message)
		}
		// summarize results
		var violated bool
		if len(violations) != 0 {
			violated = true
		} else {
			violated = false
		}
		count := len(violations)

		vrr := vrc.ManifestIntegrityStateSpec{
			ConstraintName:  constraintName,
			Violation:       violated,
			TotalViolations: count,
			Violations:      violations,
			NonViolations:   nonViolations,
			ObservationTime: time.Now().Format(timeFormat),
		}

		// check if targeted constraint
		ignored := false
		if constraint.Parameters.Action == nil {
			ignored = !rhconfig.DefaultConstraintAction.Audit.Inform

		} else {
			ignored = !constraint.Parameters.Action.Audit.Inform
		}

		// export VerifyResult
		_ = exportVerifyResult(vrr, ignored, violated)
		// VerifyResultDetail
		cres := ConstraintResult{
			ConstraintName:  constraintName,
			Results:         results,
			Violation:       violated,
			TotalViolations: count,
			Constraint:      constraint,
		}
		constraintResults = append(constraintResults, cres)
	}

	// export ConstraintResult
	res := ObservationDetailResults{
		ConstraintResults: constraintResults,
		Time:              time.Now().Format(timeFormat),
	}
	_ = exportResultDetail(res)
}

func exportVerifyResult(vrr vrc.ManifestIntegrityStateSpec, ignored bool, violated bool) error {
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		log.Error(err)
		return err
	}
	clientset, err := vrcclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return err
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}

	// label
	vv := "false"
	iv := "false"
	if violated {
		vv = "true"
	}
	if ignored {
		iv = "true"
	}
	labels := map[string]string{
		VerifyResourceViolationLabel: vv,
		VerifyResourceIgnoreLabel:    iv,
	}

	obj, err := clientset.ManifestIntegrityStates(namespace).Get(context.Background(), vrr.ConstraintName, metav1.GetOptions{})
	if err != nil || obj == nil {
		log.Info("creating new ManifestIntegrityState resource...")
		newVRC := &vrc.ManifestIntegrityState{
			ObjectMeta: metav1.ObjectMeta{
				Name: vrr.ConstraintName,
			},
			Spec: vrr,
		}

		newVRC.Labels = labels
		_, err = clientset.ManifestIntegrityStates(namespace).Create(context.Background(), newVRC, metav1.CreateOptions{})
		if err != nil {
			log.Error("failed to create ManifestIntegrityStates:", err.Error())
			return err
		}
	} else {
		log.Info("updating ManifestIntegrityStatees resource...")
		obj.Spec = vrr
		obj.Labels = labels
		_, err = clientset.ManifestIntegrityStates(namespace).Update(context.Background(), obj, metav1.UpdateOptions{})
		if err != nil {
			log.Error("failed to update ManifestIntegrityStates:", err.Error())
			return err
		}
	}
	return nil
}

func exportResultDetail(results ObservationDetailResults) error {
	exportStr := os.Getenv(exportDetailResult)
	export := defaultExportDetailResult
	if exportStr != "" {
		export, _ = strconv.ParseBool(exportStr)
	}
	if !export {
		return nil
	}

	if len(results.ConstraintResults) == 0 {
		log.Info("no observation results")
		return nil
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	configName := os.Getenv(detailResultConfigName)
	if configName == "" {
		configName = defaultObserverResultDetailConfigName
	}
	configKey := os.Getenv(detailResultConfigKey)
	if configKey == "" {
		configKey = defaultKeyInConfigMap
	}

	// load
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil
	}
	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), configName, metav1.GetOptions{})
	if err != nil {
		// create
		log.Info("creating new configmap to store verify result...", configName)
		newcm := &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: configName,
			},
		}
		resByte, _ := json.Marshal(results)
		newcm.Data = map[string]string{
			configKey: string(resByte),
		}
		_, err := clientset.CoreV1().ConfigMaps(namespace).Create(context.Background(), newcm, metav1.CreateOptions{})
		if err != nil {
			log.Error("failed to create configmap", err.Error())
			return err
		}
		return nil
	} else {
		// update
		log.Info("updating configmap ...", configName)
		resByte, _ := json.Marshal(results)
		cm.Data = map[string]string{
			configKey: string(resByte),
		}
		_, err := clientset.CoreV1().ConfigMaps(namespace).Update(context.Background(), cm, metav1.UpdateOptions{})
		if err != nil {
			log.Error("failed to update configmap", err.Error())
			return err
		}
	}
	return nil
}

func (self *Observer) getAPIResources(kubeconfig *rest.Config) error {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(kubeconfig)
	if err != nil {
		return err
	}

	apiResourceLists, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		return err
	}
	resources := []groupResource{}
	for _, apiResourceList := range apiResourceLists {
		if len(apiResourceList.APIResources) == 0 {
			continue
		}
		gv, err := schema.ParseGroupVersion(apiResourceList.GroupVersion)
		if err != nil {
			continue
		}
		for _, resource := range apiResourceList.APIResources {
			if len(resource.Verbs) == 0 {
				continue
			}
			resources = append(resources, groupResource{
				APIGroup:    gv.Group,
				APIVersion:  gv.Version,
				APIResource: resource,
			})
		}
	}
	self.APIResources = resources
	return nil
}

func (self *Observer) getAllResoucesByGroupResource(gResourceWithTargetNS groupResourceWithTargetNS) ([]unstructured.Unstructured, error) {
	var resources []unstructured.Unstructured
	var err error
	gResource := gResourceWithTargetNS.groupResource
	targetNSs := gResourceWithTargetNS.TargetNamespaces
	namespaced := gResource.APIResource.Namespaced
	gvr := schema.GroupVersionResource{
		Group:    gResource.APIGroup,
		Version:  gResource.APIVersion,
		Resource: gResource.APIResource.Name,
	}

	var tmpResourceList *unstructured.UnstructuredList
	if namespaced {
		for _, ns := range targetNSs {
			tmpResourceList, err = self.dynamicClient.Resource(gvr).Namespace(ns).List(context.Background(), metav1.ListOptions{})
			if err != nil {
				log.Error("failed to get tmpResourceList:", err.Error())
				break
			}
			resources = append(resources, tmpResourceList.Items...)
		}

	} else {
		tmpResourceList, err = self.dynamicClient.Resource(gvr).List(context.Background(), metav1.ListOptions{})
		resources = append(resources, tmpResourceList.Items...)
	}
	if err != nil {
		// ignore RBAC error - IShield SA
		log.Error("RBAC error when listing resources; error:", err.Error())
		return []unstructured.Unstructured{}, nil
	}
	return resources, nil
}

func LoadKeySecret(keySecertNamespace, keySecertName string) (string, error) {
	obj, err := kubeutil.GetResource("v1", "Secret", keySecertNamespace, keySecertName)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed to get a secret `%s` in `%s` namespace", keySecertName, keySecertNamespace))
	}
	objBytes, _ := json.Marshal(obj.Object)
	var secret v1.Secret
	_ = json.Unmarshal(objBytes, &secret)
	keyDir := fmt.Sprintf("/tmp/%s/%s/", keySecertNamespace, keySecertName)
	log.Debug("keyDir", keyDir)
	sumErr := []string{}
	keyPath := ""
	for fname, keyData := range secret.Data {
		err = os.MkdirAll(keyDir, os.ModePerm)
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
		return "", errors.New(fmt.Sprintf("no key files are found in the secret `%s` in `%s` namespace", keySecertName, keySecertNamespace))
	}

	return keyPath, nil
}

//
// Constraint
//

type ConstraintSpec struct {
	Match      MatchCondition               `json:"match,omitempty"`
	Parameters k8smnfconfig.ParameterObject `json:"parameters,omitempty"`
}

type MatchCondition struct {
	Kinds              []Kinds               `json:"kinds,omitempty"`
	Namespaces         []string              `json:"namespaces,omitempty"`
	ExcludedNamespaces []string              `json:"excludedNamespaces,omitempty"`
	LabelSelector      *metav1.LabelSelector `json:"labelSelector,omitempty"`
	NamespaceSelector  *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

type Kinds struct {
	Kinds     []string `json:"kinds,omitempty"`
	ApiGroups []string `json:"apiGroups,omitempty"`
}

func (self *Observer) loadConstraints() ([]ConstraintSpec, error) {
	gvr := schema.GroupVersionResource{
		Group:    "constraints.gatekeeper.sh",
		Version:  "v1beta1",
		Resource: "manifestintegrityconstraint",
	}
	constraintList, err := self.dynamicClient.Resource(gvr).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	micList := []ConstraintSpec{}
	for _, unstructed := range constraintList.Items {
		log.Debug("unstructed.Object", unstructed.Object)
		var mic ConstraintSpec
		spec, ok := unstructed.Object["spec"]
		if !ok {
			fmt.Println("failed to get spec in constraint", unstructed.GetName())
		}
		jsonStr, err := json.Marshal(spec)
		if err != nil {
			fmt.Println(err)
		}
		if err := json.Unmarshal(jsonStr, &mic); err != nil {
			fmt.Println(err)
		}
		log.Debug("ManigestIntegrityConstraint:", mic)
		micList = append(micList, mic)
	}
	return micList, nil
}

func (self *Observer) getPossibleProtectedGVKs(match MatchCondition) []groupResourceWithTargetNS {
	possibleProtectedGVKs := []groupResourceWithTargetNS{}
	for _, apiResource := range self.APIResources {
		matched, tmpGvks := checkIfRuleMatchWithGVK(match, apiResource)
		if matched {
			possibleProtectedGVKs = append(possibleProtectedGVKs, tmpGvks...)
		}
	}
	return possibleProtectedGVKs
}

// TODO: check logic
func checkIfRuleMatchWithGVK(match MatchCondition, apiResource groupResource) (bool, []groupResourceWithTargetNS) {
	possibleProtectedGVKs := []groupResourceWithTargetNS{}

	log.Debug("apiResource ", apiResource)
	// TODO: support "LabelSelector"
	if len(match.Kinds) == 0 {
		return false, nil
	}
	matched := false
	for _, kinds := range match.Kinds {
		kmatch := false
		agmatch := false
		if len(kinds.ApiGroups) != 0 {
			agmatch = Contains(kinds.ApiGroups, apiResource.APIGroup)
			log.Debug(fmt.Sprintf("check apiGroup condition: rule %s, apiResource.APIGroup %s, matched %s", kinds.ApiGroups, apiResource.APIGroup, strconv.FormatBool(agmatch)))
		} else {
			agmatch = true
		}
		if len(kinds.ApiGroups) != 0 {
			kmatch = Contains(kinds.Kinds, apiResource.APIResource.Kind)
		} else {
			kmatch = true
		}
		if kmatch && agmatch {
			matched = true
			namespaces := match.Namespaces
			if match.NamespaceSelector != nil {
				labeledNS := getLabelMatchedNamespace(match.NamespaceSelector)
				namespaces = append(namespaces, labeledNS...)
			}
			possibleProtectedGVKs = append(possibleProtectedGVKs, groupResourceWithTargetNS{
				groupResource:    apiResource,
				TargetNamespaces: namespaces,
			})
		}
	}
	log.WithFields(log.Fields{
		"matched":               matched,
		"possibleProtectedGVKs": possibleProtectedGVKs,
	}).Debug("check match condition")
	return matched, possibleProtectedGVKs
}

func Contains(pattern []string, value string) bool {
	for _, p := range pattern {
		if p == value {
			return true
		}
	}
	return false
}

func getLabelMatchedNamespace(labelSelector *metav1.LabelSelector) []string {
	matchedNs := []string{}
	if labelSelector == nil {
		return []string{}
	}
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return []string{}
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return []string{}
	}
	namespaces, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("failed to list a namespace:`%s`", err.Error())
		return []string{}
	}
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		log.Errorf("failed to convert the LabelSelector api type into a struct that implements labels.Selector; %s", err.Error())
		return []string{}
	}

	for _, ns := range namespaces.Items {
		labelsMap := ns.GetLabels()
		labelsSet := labels.Set(labelsMap)
		matched := selector.Matches(labelsSet)
		if matched {
			matchedNs = append(matchedNs, ns.Name)
		}
	}
	return matchedNs
}
