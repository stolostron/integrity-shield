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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	log "github.com/sirupsen/logrus"
	k8smnfconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	ishieldimage "github.com/stolostron/integrity-shield/shield/pkg/image"
	kubeutil "github.com/stolostron/integrity-shield/shield/pkg/kubernetes"
	v1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kubeclient "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const defaultPodNamespace = "integrity-shield-operator-system"
const ImageRefAnnotationKeyShield = "integrityshield.io/signature"
const AnnotationKeyDomain = "integrityshield.io"
const SignatureAnnotationTypeShield = "IntegrityShield"
const SignatureResourceLabel = "integrityshield.io/signatureResource"
const (
	EventTypeAnnotationKey       = "integrityshield.io/eventType"
	EventResultAnnotationKey     = "integrityshield.io/eventResult"
	EventTypeValueVerifyResult   = "verify-result"
	EventTypeAnnotationValueDeny = "deny"
)
const timeFormat = "2006-01-02T15:04:05Z"

func RequestHandler(req admission.Request, paramObj *k8smnfconfig.ParameterObj) *ResultFromRequestHandler {

	// unmarshal admission request object
	var resource unstructured.Unstructured
	objectBytes := req.AdmissionRequest.Object.Raw
	err := json.Unmarshal(objectBytes, &resource)
	if err != nil {
		log.Errorf("failed to Unmarshal a requested object into %T; %s", resource, err.Error())
		errMsg := "IntegrityShield failed to decide the response. Failed to Unmarshal a requested object: " + err.Error()
		return makeResultFromRequestHandler(false, errMsg, false, req)
	}

	var oldResource unstructured.Unstructured
	oldObjectBytes := req.AdmissionRequest.OldObject.Raw
	if oldObjectBytes != nil {
		err = json.Unmarshal(oldObjectBytes, &oldResource)
		if err != nil {
			log.Errorf("failed to Unmarshal a requested oldObject into %T; %s", resource, err.Error())
			errMsg := "IntegrityShield failed to decide the response. Failed to Unmarshal a requested object: " + err.Error()
			return makeResultFromRequestHandler(false, errMsg, false, req)
		}
	}

	// load request handler config
	namespace := os.Getenv("POD_NAMESPACE")
	rhcm := os.Getenv("REQUEST_HANDLER_CONFIG_NAME")
	rhconfig, err := k8smnfconfig.LoadRequestHandlerConfig(namespace, rhcm)
	if err != nil {
		log.Errorf("failed to load request handler config: %s", err.Error())
		errMsg := "IntegrityShield failed to decide the response. Failed to load request handler config: " + err.Error()
		return makeResultFromRequestHandler(false, errMsg, false, req)
	}
	if rhconfig == nil {
		log.Warning("request handler config is empty")
		rhconfig = &k8smnfconfig.RequestHandlerConfig{}
	}

	// setup log
	k8smnfconfig.SetupLogger(rhconfig.Log)
	decisionReporter := k8smnfconfig.InitDecisionReporter(rhconfig.DecisionReporterConfig)
	if paramObj.ConstraintName == "" {
		log.Warning("ConstraintName is empty. Please set constraint name in parameter field.")
	}
	logRecord := map[string]interface{}{
		"namespace":      req.Namespace,
		"name":           req.Name,
		"apiGroup":       req.RequestResource.Group,
		"apiVersion":     req.RequestResource.Version,
		"kind":           req.Kind.Kind,
		"resource":       req.RequestResource.Resource,
		"userName":       req.UserInfo.Username,
		"constraintName": paramObj.ConstraintName,
		"admissionTime":  time.Now().Format(timeFormat),
	}

	log.WithFields(log.Fields{
		"namespace": req.Namespace,
		"name":      req.Name,
		"kind":      req.Kind.Kind,
		"operation": req.Operation,
		"userName":  req.UserInfo.Username,
	}).Info("Process new request")

	// get enforce action
	enforce := false
	if paramObj.Action == nil {
		if rhconfig.DefaultConstraintAction.Mode != "" {
			if rhconfig.DefaultConstraintAction.Mode == "enforce" {
				enforce = true
			}
		}
	} else {
		if paramObj.Action.Mode != "enforce" && paramObj.Action.Mode != "inform" {
			log.WithFields(log.Fields{
				"namespace": req.Namespace,
				"name":      req.Name,
				"kind":      req.Kind.Kind,
				"operation": req.Operation,
				"userName":  req.UserInfo.Username,
			}).Warningf("run mode should be set to 'enforce' or 'inform' in rule,%s", paramObj.ConstraintName)
		}
		if paramObj.Action.Mode == "enforce" {
			enforce = true
		}
	}
	if enforce {
		log.Info("enforce action is enabled.")
	} else {
		log.Info("enforce action is disabled.")
	}
	allow := false
	message := ""
	signatureResource := false
	// check if signature resource
	signatureResource = isAllowedSignatureResource(resource, req.AdmissionRequest.OldObject.Raw, req.Operation)
	if signatureResource {
		allow = true
		message = "allowed because this resource is signatureResource."
		return makeResultFromRequestHandler(allow, message, enforce, req)
	}

	// verify resource
	err, allow, message = ResourceVerify(resource, oldResource, req.UserInfo.Username, string(req.Operation), rhconfig.RequestFilterProfile, &paramObj.ManifestIntegrityConstraint)
	if err != nil {
		log.Errorf("IntegrityShield failed to decide the response. ", err.Error())
		return makeResultFromRequestHandler(allow, message, enforce, req)
	}

	// report decision log if skip user
	if allow && message == "SkipUsers rule matched." {
		logRecord["reason"] = message
		logRecord["allow"] = allow
		decisionReporter.SendLog(logRecord)
	}

	// verify image
	imageAllow := true
	imageMessage := ""
	var imageVerifyResults []ishieldimage.ImageVerifyResult
	if paramObj.ImageProfile.Enabled() {
		_, err = ishieldimage.VerifyImageInManifest(resource, paramObj.ImageProfile)
		if err != nil {
			log.Errorf("failed to verify images: %s", err.Error())
			imageAllow = false
			imageMessage = "Image signature verification is required, but failed to verify signature: " + err.Error()

		} else {
			for _, res := range imageVerifyResults {
				if res.InScope && !res.Verified {
					imageAllow = false
					imageMessage = "Image signature verification is required, but failed to verify signature: " + res.FailReason
					break
				}
			}
		}
	}

	if allow && !imageAllow {
		message = imageMessage
		allow = false
	}

	r := makeResultFromRequestHandler(allow, message, enforce, req)
	// generate events
	if rhconfig.SideEffectConfig.CreateDenyEvent {
		_ = createOrUpdateEvent(req, r, paramObj.ConstraintName)
	}
	return r
}

type ResultFromRequestHandler struct {
	Allow   bool   `json:"allow"`
	Message string `json:"message"`
	// Profile string `json:"profile,omitempty"`
}

func makeResultFromRequestHandler(allow bool, msg string, enforce bool, req admission.Request) *ResultFromRequestHandler {
	res := &ResultFromRequestHandler{}
	res.Allow = allow
	res.Message = msg
	if !allow && !enforce {
		res.Allow = true
		res.Message = fmt.Sprintf("allowed because not enforced: %s", msg)

	}
	log.WithFields(log.Fields{
		"namespace": req.Namespace,
		"name":      req.Name,
		"kind":      req.Kind.Kind,
		"operation": req.Operation,
		"userName":  req.UserInfo.Username,
		"allow":     res.Allow,
	}).Info(res.Message)
	return res
}

func isUpdateRequest(operation v1.Operation) bool {
	return (operation == v1.Update)
}

func isAllowedSignatureResource(resource unstructured.Unstructured, oldObj []byte, operation v1.Operation) bool {
	var currentResourceLabel bool
	var label bool
	if !(resource.GetKind() == "ConfigMap") {
		return label
	}
	label = isSignatureResource(resource)
	if operation == v1.Create {
		currentResourceLabel = true
	} else if operation == v1.Update {
		// unmarshal admission request object
		var oldRes unstructured.Unstructured
		err := json.Unmarshal(oldObj, &oldRes)
		if err != nil {
			log.Errorf("failed to Unmarshal a requested object into %T; %s", resource, err.Error())
		}
		currentResourceLabel = isSignatureResource(oldRes)
	}
	return (label && currentResourceLabel)
}

func isSignatureResource(resource unstructured.Unstructured) bool {
	var label bool
	labelsMap := resource.GetLabels()
	_, found := labelsMap[SignatureResourceLabel]
	if found {
		label = true
	}
	return label
}

func getMatchedIgnoreFields(pi, ci k8smanifest.ObjectFieldBindingList, resource unstructured.Unstructured) []string {
	var allIgnoreFields []string
	_, fields := pi.Match(resource)
	_, commonfields := ci.Match(resource)
	allIgnoreFields = append(allIgnoreFields, fields...)
	allIgnoreFields = append(allIgnoreFields, commonfields...)
	return allIgnoreFields
}

func mutationCheck(rawOldObject, rawObject []byte, IgnoreFields []string) (bool, error) {
	var oldObject *mapnode.Node
	var newObject *mapnode.Node
	mask := []string{
		"metadata.annotations.namespace",
		"metadata.annotations.kubectl.\"kubernetes.io/last-applied-configuration\"",
		"metadata.annotations.deprecated.daemonset.template.generation",
		"metadata.creationTimestamp",
		"metadata.uid",
		"metadata.generation",
		"metadata.managedFields",
		"metadata.selfLink",
		"metadata.resourceVersion",
		"status",
	}
	if v, err := mapnode.NewFromBytes(rawObject); err != nil || v == nil {
		return false, err
	} else {
		v = v.Mask(mask)
		obj := v.ToMap()
		newObject, _ = mapnode.NewFromMap(obj)
	}
	if v, err := mapnode.NewFromBytes(rawOldObject); err != nil || v == nil {
		return false, err
	} else {
		v = v.Mask(mask)
		oldObj := v.ToMap()
		oldObject, _ = mapnode.NewFromMap(oldObj)
	}
	// diff
	dr := oldObject.Diff(newObject)
	if dr == nil || dr.Size() == 0 {
		return false, nil
	}
	// ignoreField check
	unfiltered := &mapnode.DiffResult{}
	if dr != nil && dr.Size() > 0 {
		_, unfiltered, _ = dr.Filter(IgnoreFields)
	}
	if unfiltered.Size() == 0 {
		return false, nil
	}
	return true, nil
}

func setVerifyOption(paramObj *k8smnfconfig.ManifestIntegrityConstraint, commonProfile *k8smnfconfig.RequestFilterProfile, signatureAnnotationType string) *k8smanifest.VerifyResourceOption {
	// get verifyOption and imageRef from Parameter
	vo := &paramObj.VerifyResourceOption

	// set Signature ref
	if paramObj.SignatureRef.ImageRef != "" {
		vo.ImageRef = paramObj.SignatureRef.ImageRef
	}
	if paramObj.SignatureRef.SignatureResourceRef.Name != "" && paramObj.SignatureRef.SignatureResourceRef.Namespace != "" {
		ref := fmt.Sprintf("k8s://ConfigMap/%s/%s", paramObj.SignatureRef.SignatureResourceRef.Namespace, paramObj.SignatureRef.SignatureResourceRef.Name)
		vo.SignatureResourceRef = ref
	}
	if paramObj.SignatureRef.ProvenanceResourceRef.Name != "" && paramObj.SignatureRef.ProvenanceResourceRef.Namespace != "" {
		ref := fmt.Sprintf("k8s://ConfigMap/%s/%s", paramObj.SignatureRef.ProvenanceResourceRef.Namespace, paramObj.SignatureRef.ProvenanceResourceRef.Name)
		vo.ProvenanceResourceRef = ref
	}

	// set DryRun namespace
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	vo.DryRunNamespace = namespace

	// set Signature type
	if signatureAnnotationType == SignatureAnnotationTypeShield {
		vo.AnnotationConfig.AnnotationKeyDomain = AnnotationKeyDomain
	}
	// prepare local key for verifyResource
	if len(paramObj.KeyConfigs) != 0 {
		keyPathList := []string{}
		for _, keyconfig := range paramObj.KeyConfigs {
			if keyconfig.KeySecretName != "" {
				keyPath, err := k8smnfconfig.LoadKeySecret(keyconfig.KeySecretNamespace, keyconfig.KeySecretName)
				if err != nil {
					log.Errorf("failed to load key secret: %s", err.Error())
				}
				keyPathList = append(keyPathList, keyPath)
			}
		}
		keyPathString := strings.Join(keyPathList, ",")
		if keyPathString != "" {
			vo.KeyPath = keyPathString
		}
	}
	// merge params in common profile
	if len(commonProfile.IgnoreFields) == 0 {
		return vo
	}
	fields := k8smanifest.ObjectFieldBindingList{}
	fields = append(fields, vo.IgnoreFields...)
	fields = append(fields, commonProfile.IgnoreFields...)
	vo.IgnoreFields = fields
	return vo
}

func skipObjectsMatch(l k8smanifest.ObjectReferenceList, obj unstructured.Unstructured) bool {
	if len(l) == 0 {
		return false
	}
	for _, r := range l {
		if r.Match(obj) {
			return true
		}
	}
	return false
}

func createOrUpdateEvent(req admission.Request, ar *ResultFromRequestHandler, constraintName string) error {
	// no event is generated for allowed request
	if ar.Allow {
		return nil
	}

	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return err
	}
	client, err := kubeclient.NewForConfig(config)
	if err != nil {
		return err
	}

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	gv := schema.GroupVersion{Group: req.Kind.Group, Version: req.Kind.Version}
	evtNamespace := req.Namespace
	if evtNamespace == "" {
		evtNamespace = namespace
	}
	involvedObject := corev1.ObjectReference{
		Namespace:  req.Namespace,
		APIVersion: gv.String(),
		Kind:       req.Kind.Kind,
		Name:       req.Name,
	}
	evtName := fmt.Sprintf("ishield-deny-%s-%s-%s", strings.ToLower(string(req.Operation)), strings.ToLower(req.Kind.Kind), req.Name)
	sourceName := "IntegrityShield"

	now := time.Now()
	evt := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      evtName,
			Namespace: evtNamespace,
			Annotations: map[string]string{
				EventTypeAnnotationKey:   EventTypeValueVerifyResult,
				EventResultAnnotationKey: EventTypeAnnotationValueDeny,
			},
		},
		InvolvedObject:      involvedObject,
		Type:                sourceName,
		Source:              corev1.EventSource{Component: sourceName},
		ReportingController: sourceName,
		ReportingInstance:   evtName,
		Action:              evtName,
		Reason:              "Deny",
		FirstTimestamp:      metav1.NewTime(now),
	}
	isExistingEvent := false
	current, getErr := client.CoreV1().Events(evtNamespace).Get(context.Background(), evtName, metav1.GetOptions{})
	if current != nil && getErr == nil {
		isExistingEvent = true
		evt = current
	}

	tmpMessage := "[" + constraintName + "]" + ar.Message
	// tmpMessage := ar.Message
	// Event.Message can have 1024 chars at most
	if len(tmpMessage) > 1024 {
		tmpMessage = tmpMessage[:950] + " ... Trimmed. `Event.Message` can have 1024 chars at maximum."
	}
	evt.Message = tmpMessage
	evt.Count = evt.Count + 1
	evt.EventTime = metav1.NewMicroTime(now)
	evt.LastTimestamp = metav1.NewTime(now)

	if isExistingEvent {
		_, err = client.CoreV1().Events(evtNamespace).Update(context.Background(), evt, metav1.UpdateOptions{})
	} else {
		_, err = client.CoreV1().Events(evtNamespace).Create(context.Background(), evt, metav1.CreateOptions{})
	}
	if err != nil {
		log.Errorf("failed to generate deny event: %s", err.Error())
		return err
	}

	log.WithFields(log.Fields{
		"namespace": req.Namespace,
		"name":      req.Name,
		"kind":      req.Kind.Kind,
		"operation": req.Operation,
	}).Debug("Deny event is generated:", evtName)

	return nil
}
