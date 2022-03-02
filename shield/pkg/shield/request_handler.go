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
	"fmt"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	log "github.com/sirupsen/logrus"
	k8smnfconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	kubeutil "github.com/stolostron/integrity-shield/shield/pkg/kubernetes"
	kubeclient "k8s.io/client-go/kubernetes"

	// "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	admission "k8s.io/api/admission/v1beta1"

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

func RequestHandler(req *admission.AdmissionRequest, paramObj *k8smnfconfig.ParameterObject) *ResultFromRequestHandler {
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
			}).Warningf("Run mode should be set to 'enforce' or 'inform' in rule,%s", paramObj.ConstraintName)
		}
		if paramObj.Action.Mode == "enforce" {
			enforce = true
		}
	}
	if enforce {
		log.Info("Enforce action is enabled.")
	} else {
		log.Info("Enforce action is disabled.")
	}

	// start request verification
	allow := false
	message := ""

	// prepare manifest verify config
	dryRunNs := os.Getenv("POD_NAMESPACE")
	if dryRunNs == "" {
		dryRunNs = defaultPodNamespace
	}
	mvConfig := &k8smnfconfig.ManifestVerifyConfig{
		RequestFilterProfile: rhconfig.RequestFilterProfile,
		DryRunNamespcae:      dryRunNs,
	}

	// verify resource
	allow, message, err = VerifyResource(req, mvConfig, &paramObj.ManifestVerifyRule)
	if err != nil {
		log.Errorf("IntegrityShield failed to decide the response. ", err.Error())
		return makeResultFromRequestHandler(allow, message, enforce, req)
	}

	// report decision log if skip user
	if allow && message == SkipUser {
		logRecord["reason"] = message
		logRecord["allow"] = allow
		decisionReporter.SendLog(logRecord)
	}

	// verify image
	imageAllow, imageMessage := VerifyImagesInManifest(req, paramObj.ImageProfile)
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
}

func makeResultFromRequestHandler(allow bool, msg string, enforce bool, req *admission.AdmissionRequest) *ResultFromRequestHandler {
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

func createOrUpdateEvent(req *admission.AdmissionRequest, ar *ResultFromRequestHandler, constraintName string) error {
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
