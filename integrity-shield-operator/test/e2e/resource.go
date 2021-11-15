// Copyright 2021  IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2e

import (
	"context"
	goctx "context"
	"fmt"
	"strings"
	"time"

	"github.com/ghodss/yaml"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/duration"
)

// IsPodReady returns true if a pod is ready; false otherwise.
func IsPodReady(pod *corev1.Pod) bool {
	return IsPodReadyConditionTrue(pod.Status)
}

// IsPodReadyConditionTrue returns true if a pod is ready; false otherwise.
func IsPodReadyConditionTrue(status corev1.PodStatus) bool {
	condition := GetPodReadyCondition(status)
	return condition != nil && condition.Status == corev1.ConditionTrue
}

// GetPodReadyCondition extracts the pod ready condition from the given status and returns that.
// Returns nil if the condition is not present.
func GetPodReadyCondition(status corev1.PodStatus) *corev1.PodCondition {
	_, condition := GetPodCondition(&status, corev1.PodReady)
	return condition
}

// GetPodCondition extracts the provided condition from the given status and returns that.
// Returns nil and -1 if the condition is not present, and the index of the located condition.
func GetPodCondition(status *corev1.PodStatus, conditionType corev1.PodConditionType) (int, *corev1.PodCondition) {
	if status == nil {
		return -1, nil
	}
	for i := range status.Conditions {
		if status.Conditions[i].Type == conditionType {
			return i, &status.Conditions[i]
		}
	}
	return -1, nil
}

func IsTargetPodReadyConditionTrue(pods *corev1.PodList, expected string) (found, ready bool) {
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, expected) {
			for _, pod := range pods.Items {
				if strings.HasPrefix(pod.Name, expected) {
					is_ready := IsPodReadyConditionTrue(pod.Status)
					return true, is_ready
				}
			}
		}
	}
	return false, false
}

func CheckPodStatus(framework *Framework, namespace, expected string) error {
	pods, err := framework.KubeClientSet.CoreV1().Pods(namespace).List(goctx.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	pod_exist, ready := IsTargetPodReadyConditionTrue(pods, expected)
	if !pod_exist {
		return fmt.Errorf("Pod is not found: %v", expected)
	}
	if pod_exist && !ready {
		DescribePod(framework, namespace, expected)
		return fmt.Errorf("Pod is not ready: %v", expected)
	}
	return nil
}

func DescribePod(framework *Framework, namespace, expected string) {
	ShowPodStatus(framework, namespace, expected)
	ShowEventsForPod(framework, namespace, expected)
}

func ShowPodStatus(framework *Framework, namespace, expected string) {
	name := GetPodName(framework, namespace, expected)
	if name == "" {
		fmt.Printf("failed to find a Pod that name starts with `%s`.\n", expected)
		return
	}
	pod, err := framework.KubeClientSet.CoreV1().Pods(namespace).Get(goctx.TODO(), name, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("failed to get pod, error: %s\n", err.Error())
		return
	}
	fmt.Printf("Showing status of Pod `%s`\n", name)
	podStatusBytes, err := yaml.Marshal(pod.Status)
	if err != nil {
		fmt.Printf("failed to marshal pod status, error: %s\n", err.Error())
		return
	}
	fmt.Println(string(podStatusBytes))
}

func ShowEventsForPod(framework *Framework, namespace, expected string) {
	name := GetPodName(framework, namespace, expected)
	if name == "" {
		fmt.Printf("failed to find a Pod that name starts with `%s`.\n", expected)
		return
	}
	eventsInterface := framework.KubeClientSet.CoreV1().Events(namespace)
	selector := eventsInterface.GetFieldSelector(&name, &namespace, nil, nil)
	initialOpts := metav1.ListOptions{
		FieldSelector: selector.String(),
		Limit:         500, //default chunk size of kubectl describe
	}
	events, err := eventsInterface.List(context.Background(), initialOpts)
	if err != nil {
		fmt.Printf("failed to list events, error: %s\n", err.Error())
		return
	}
	if len(events.Items) == 0 {
		fmt.Printf("there are no events related to the Pod `%s`.\n", name)
		return
	}
	fmt.Printf("showing events related to the Pod `%s`.\n", name)
	fmt.Printf("Events:\n  Type\tReason\tAge\tFrom\tMessage\n")
	fmt.Printf("  ----\t------\t----\t----\t-------\n")
	for _, e := range events.Items {
		var interval string
		firstTimestampSince := translateMicroTimestampSince(e.EventTime)
		if e.EventTime.IsZero() {
			firstTimestampSince = translateTimestampSince(e.FirstTimestamp)
		}
		if e.Series != nil {
			interval = fmt.Sprintf("%s (x%d over %s)", translateMicroTimestampSince(e.Series.LastObservedTime), e.Series.Count, firstTimestampSince)
		} else if e.Count > 1 {
			interval = fmt.Sprintf("%s (x%d over %s)", translateTimestampSince(e.LastTimestamp), e.Count, firstTimestampSince)
		} else {
			interval = firstTimestampSince
		}
		source := e.Source.Component
		if source == "" {
			source = e.ReportingController
		}
		fmt.Printf("  %v\t%v\t%s\t%v\t%v\n",
			e.Type,
			e.Reason,
			interval,
			source,
			strings.TrimSpace(e.Message),
		)
	}
}

func translateMicroTimestampSince(timestamp metav1.MicroTime) string {
	if timestamp.IsZero() {
		return "<unknown>"
	}
	return duration.HumanDuration(time.Since(timestamp.Time))
}

func translateTimestampSince(timestamp metav1.Time) string {
	if timestamp.IsZero() {
		return "<unknown>"
	}
	return duration.HumanDuration(time.Since(timestamp.Time))
}

func GetPodName(framework *Framework, namespace, expected string) string {
	pods, err := framework.KubeClientSet.CoreV1().Pods(namespace).List(goctx.TODO(), metav1.ListOptions{})
	if err != nil {
		return ""
	}
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, expected) {
			return pod.Name
		}
	}
	return ""
}

func CheckConfigMap(framework *Framework, namespace, expected string) error {
	_, err := framework.KubeClientSet.CoreV1().ConfigMaps(namespace).Get(goctx.TODO(), expected, metav1.GetOptions{})
	if err != nil {
		return err
	}
	return nil
}

func CheckDeployment(framework *Framework, namespace, expected string) error {
	_, err := framework.KubeClientSet.AppsV1().Deployments(namespace).Get(goctx.TODO(), expected, metav1.GetOptions{})
	if err != nil {
		return err
	}
	return nil
}

func LoadConfigMap(framework *Framework, namespace, expected string) (error, *corev1.ConfigMap) {
	cm, err := framework.KubeClientSet.CoreV1().ConfigMaps(namespace).Get(goctx.TODO(), expected, metav1.GetOptions{})
	if err != nil {
		return err, nil
	}
	return nil, cm
}

func GetSecretName(framework *Framework, namespace, expected string) (string, error) {
	secrets, err := framework.KubeClientSet.CoreV1().Secrets(namespace).List(goctx.TODO(), metav1.ListOptions{})
	if err != nil {
		return "", err
	}
	for _, secret := range secrets.Items {
		if strings.HasPrefix(secret.Name, expected) {
			return secret.Name, nil
		}
	}
	return "", fmt.Errorf("Fail to get secret: %v", expected)
}

func CheckIShieldResources(framework *Framework, kind, namespace, expected string) error {
	if kind == "Deployment" {
		_, err := framework.KubeClientSet.AppsV1().Deployments(namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	if kind == "PodSecurityPolicy" {
		_, err := framework.KubeClientSet.ExtensionsV1beta1().PodSecurityPolicies().Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	if kind == "CustomResourceDefinition" {
		_, err := framework.APIExtensionsClientSet.ApiextensionsV1().CustomResourceDefinitions().Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	if kind == "Secret" {
		_, err := framework.KubeClientSet.CoreV1().Secrets(namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	if kind == "Service" {
		_, err := framework.KubeClientSet.CoreV1().Services(namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	if kind == "ServiceAccount" {
		_, err := framework.KubeClientSet.CoreV1().ServiceAccounts(namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	if kind == "ClusterRole" {
		_, err := framework.KubeClientSet.RbacV1().ClusterRoles().Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	if kind == "ClusterRoleBinding" {
		_, err := framework.KubeClientSet.RbacV1().ClusterRoleBindings().Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	if kind == "Role" {
		_, err := framework.KubeClientSet.RbacV1().Roles(namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	if kind == "RoleBinding" {
		_, err := framework.KubeClientSet.RbacV1().RoleBindings(namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	if kind == "ConfigMap" {
		_, err := framework.KubeClientSet.CoreV1().ConfigMaps(namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	if kind == "ManifestIntegrityProfile" {
		_, err := framework.MIPClient.ManifestIntegrityProfiles().Get(goctx.Background(), expected, metav1.GetOptions{})
		return err
	}
	return fmt.Errorf("Fail to call resource type: %v", kind)
}
