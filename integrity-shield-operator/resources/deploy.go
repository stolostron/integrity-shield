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

package resources

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	apiv1 "github.com/open-cluster-management/integrity-shield/integrity-shield-operator/api/v1"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	intstr "k8s.io/apimachinery/pkg/util/intstr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("controller_integrityshield")

//deployment
// shield api
func BuildDeploymentForIShieldAPI(cr *apiv1.IntegrityShield) *appsv1.Deployment {
	var volumemounts []v1.VolumeMount
	var volumes []v1.Volume
	labels := cr.Spec.MetaLabels
	volumes = []v1.Volume{
		SecretVolume("ishield-api-certs", cr.Spec.APITlsSecretName),
		EmptyDirVolume("tmp"),
		EmptyDirVolume("report-volume"),
	}
	if cr.Spec.OCIRegistryConfig.ManifestPullSecret != "" {
		volumes = append(volumes, SecretVolume("docker-creds", cr.Spec.OCIRegistryConfig.ManifestPullSecret))
	}

	volumemounts = []v1.VolumeMount{
		{
			MountPath: "/run/secrets/tls",
			Name:      "ishield-api-certs",
			ReadOnly:  true,
		},
		{
			MountPath: "/tmp",
			Name:      "tmp",
		},
		{
			MountPath: "/ishield-app/shared",
			Name:      "report-volume",
		},
	}
	if cr.Spec.OCIRegistryConfig.ManifestPullSecret != "" {
		volumemounts = append(volumemounts, v1.VolumeMount{
			MountPath: "/run/secrets/docker",
			Name:      "docker-creds",
			ReadOnly:  true,
		})
	}

	loggerVolumemounts := []v1.VolumeMount{
		{
			MountPath: "/tmp",
			Name:      "tmp",
		},
		{
			MountPath: "/ishield-app/shared",
			Name:      "report-volume",
		},
	}

	var image string
	if cr.Spec.API.Tag != "" {
		image = SetImageVersion(cr.Spec.API.Image, cr.Spec.API.Tag, cr.Spec.API.Name)
	} else {
		version := GetVersion(cr.Spec.API.Name)
		image = SetImageVersion(cr.Spec.API.Image, version, cr.Spec.API.Name)
	}

	env := []v1.EnvVar{
		{
			Name:  "POD_NAMESPACE",
			Value: cr.Namespace,
		},
		{
			Name:  "REQUEST_HANDLER_CONFIG_KEY",
			Value: cr.Spec.RequestHandlerConfigKey,
		},
		{
			Name:  "REQUEST_HANDLER_CONFIG_NAME",
			Value: cr.Spec.RequestHandlerConfigName,
		},
		{
			Name:  "DECISION_FILE_PATH",
			Value: apiv1.DefaultFilePath,
		},
		{
			Name:  "REKOR_SERVER",
			Value: cr.Spec.RekorServerConfig.URL,
		},
	}
	if cr.Spec.OCIRegistryConfig.ManifestPullSecret != "" {
		env = append(env, v1.EnvVar{
			Name:  "DOCKER_CONFIG",
			Value: "/run/secrets/docker",
		})
	}

	var reporterImage string
	if cr.Spec.Reporter.Tag != "" {
		reporterImage = SetImageVersion(cr.Spec.Reporter.Image, cr.Spec.Reporter.Tag, cr.Spec.Reporter.Name)
	} else {
		version := GetVersion(cr.Spec.Reporter.Name)
		reporterImage = SetImageVersion(cr.Spec.Reporter.Image, version, cr.Spec.Reporter.Name)
	}
	apiContainer := v1.Container{
		Name:            cr.Spec.API.Name,
		SecurityContext: cr.Spec.API.SecurityContext,
		Image:           image,
		ImagePullPolicy: cr.Spec.API.ImagePullPolicy,
		ReadinessProbe: &v1.Probe{
			InitialDelaySeconds: 10,
			PeriodSeconds:       10,
			Handler: v1.Handler{
				HTTPGet: &v1.HTTPGetAction{
					Path:   "/health/readiness",
					Port:   intstr.IntOrString{IntVal: 8080},
					Scheme: v1.URISchemeHTTPS,
				},
			},
		},
		LivenessProbe: &v1.Probe{
			InitialDelaySeconds: 10,
			PeriodSeconds:       10,
			Handler: v1.Handler{
				HTTPGet: &v1.HTTPGetAction{
					Path:   "/health/liveness",
					Port:   intstr.IntOrString{IntVal: 8080},
					Scheme: v1.URISchemeHTTPS,
				},
			},
		},
		Ports: []v1.ContainerPort{
			{
				Name:          "ishield-api",
				ContainerPort: cr.Spec.API.Port,
				Protocol:      v1.ProtocolTCP,
			},
		},
		VolumeMounts: volumemounts,
		Env:          env,
		Resources:    cr.Spec.API.Resources,
	}
	reporterContainer := v1.Container{
		Name:            cr.Spec.Reporter.Name,
		SecurityContext: cr.Spec.Reporter.SecurityContext,
		Image:           reporterImage,
		ImagePullPolicy: cr.Spec.Reporter.ImagePullPolicy,
		ReadinessProbe: &v1.Probe{
			InitialDelaySeconds: 10,
			PeriodSeconds:       10,
			Handler: v1.Handler{
				HTTPGet: &v1.HTTPGetAction{
					Path:   "/health/readiness",
					Port:   intstr.IntOrString{IntVal: 8080},
					Scheme: v1.URISchemeHTTPS,
				},
			},
		},
		LivenessProbe: &v1.Probe{
			InitialDelaySeconds: 10,
			PeriodSeconds:       10,
			Handler: v1.Handler{
				HTTPGet: &v1.HTTPGetAction{
					Path:   "/health/liveness",
					Port:   intstr.IntOrString{IntVal: 8080},
					Scheme: v1.URISchemeHTTPS,
				},
			},
		},
		VolumeMounts: loggerVolumemounts,
		Env: []v1.EnvVar{
			{
				Name:  "POD_NAMESPACE",
				Value: cr.Namespace,
			},
			{
				Name:  "INTERVAL_SECONDS",
				Value: cr.Spec.Reporter.IntervalSeconds,
			},
			{
				Name:  "DECISION_FILE_PATH",
				Value: apiv1.DefaultFilePath,
			},
		},
		Resources: cr.Spec.Reporter.Resources,
	}
	containers := []v1.Container{
		apiContainer,
		reporterContainer,
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.API.Name,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       cr.Spec.MaxSurge,
					MaxUnavailable: cr.Spec.MaxUnavailable,
				},
			},
			Replicas: cr.Spec.ReplicaCount,
			Selector: &metav1.LabelSelector{
				MatchLabels: cr.Spec.API.SelectorLabels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: cr.Spec.API.SelectorLabels,
				},
				Spec: v1.PodSpec{
					ServiceAccountName: cr.Spec.Security.APIServiceAccountName,
					SecurityContext:    cr.Spec.Security.PodSecurityContext,
					Containers:         containers,
					NodeSelector:       cr.Spec.NodeSelector,
					Affinity:           cr.Spec.Affinity,
					Tolerations:        cr.Spec.Tolerations,
					Volumes:            volumes,
				},
			},
		},
	}
}

// admission controller
func BuildDeploymentForAdmissionController(cr *apiv1.IntegrityShield) *appsv1.Deployment {
	labels := cr.Spec.MetaLabels

	volumes := []v1.Volume{
		SecretVolume("webhook-tls", cr.Spec.WebhookServerTlsSecretName),
		EmptyDirVolume("tmp"),
		EmptyDirVolume("report-volume"),
	}
	if cr.Spec.OCIRegistryConfig.ManifestPullSecret != "" {
		volumes = append(volumes, SecretVolume("docker-creds", cr.Spec.OCIRegistryConfig.ManifestPullSecret))
	}

	servervolumemounts := []v1.VolumeMount{
		{
			MountPath: "/run/secrets/tls",
			Name:      "webhook-tls",
			ReadOnly:  true,
		},
		{
			MountPath: "/run/secrets/docker",
			Name:      "docker-creds",
			ReadOnly:  true,
		},
		{
			MountPath: "/tmp",
			Name:      "tmp",
		},
	}
	if cr.Spec.OCIRegistryConfig.ManifestPullSecret != "" {
		servervolumemounts = append(servervolumemounts, v1.VolumeMount{
			MountPath: "/run/secrets/docker",
			Name:      "docker-creds",
			ReadOnly:  true,
		})
	}

	var image string
	if cr.Spec.ControllerContainer.Tag != "" {
		image = SetImageVersion(cr.Spec.ControllerContainer.Image, cr.Spec.ControllerContainer.Tag, cr.Spec.ControllerContainer.Name)
	} else {
		version := GetVersion(cr.Spec.ControllerContainer.Name)
		image = SetImageVersion(cr.Spec.ControllerContainer.Image, version, cr.Spec.ControllerContainer.Name)
	}

	env := []v1.EnvVar{
		{
			Name:  "POD_NAMESPACE",
			Value: cr.Namespace,
		},
		{
			Name:  "LOG_LEVEL",
			Value: cr.Spec.ControllerContainer.Log.LogLevel,
		},
		{
			Name:  "LOG_FORMAT",
			Value: cr.Spec.ControllerContainer.Log.LogFormat,
		},
		{
			Name:  "CONTROLLER_CONFIG_KEY",
			Value: cr.Spec.AdmissionControllerConfigKey,
		},
		{
			Name:  "CONTROLLER_CONFIG_NAME",
			Value: cr.Spec.AdmissionControllerConfigName,
		},
		{
			Name:  "REQUEST_HANDLER_CONFIG_KEY",
			Value: cr.Spec.RequestHandlerConfigKey,
		},
		{
			Name:  "REQUEST_HANDLER_CONFIG_NAME",
			Value: cr.Spec.RequestHandlerConfigName,
		},
		{
			Name:  "REKOR_SERVER",
			Value: cr.Spec.RekorServerConfig.URL,
		},
	}
	if cr.Spec.OCIRegistryConfig.ManifestPullSecret != "" {
		env = append(env, v1.EnvVar{
			Name:  "DOCKER_CONFIG",
			Value: "/run/secrets/docker",
		})
	}

	serverContainer := v1.Container{
		Command: []string{
			"/myapp/k8s-manifest-sigstore",
		},
		Name:            cr.Spec.ControllerContainer.Name,
		SecurityContext: cr.Spec.ControllerContainer.SecurityContext,
		Image:           image,
		ImagePullPolicy: cr.Spec.ControllerContainer.ImagePullPolicy,
		ReadinessProbe: &v1.Probe{
			Handler: v1.Handler{
				Exec: &v1.ExecAction{
					Command: []string{
						"ls",
					},
				},
			},
		},
		LivenessProbe: &v1.Probe{
			Handler: v1.Handler{
				Exec: &v1.ExecAction{
					Command: []string{
						"ls",
					},
				},
			},
		},
		Ports: []v1.ContainerPort{
			{
				Name:          "validator-port",
				ContainerPort: cr.Spec.ControllerContainer.Port,
				Protocol:      v1.ProtocolTCP,
			},
		},
		VolumeMounts: servervolumemounts,
		Env:          env,
		Resources:    cr.Spec.ControllerContainer.Resources,
	}

	containers := []v1.Container{
		serverContainer,
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.ControllerContainer.Name,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       cr.Spec.MaxSurge,
					MaxUnavailable: cr.Spec.MaxUnavailable,
				},
			},
			Replicas: cr.Spec.ReplicaCount,
			Selector: &metav1.LabelSelector{
				MatchLabels: cr.Spec.ControllerContainer.SelectorLabels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: cr.Spec.ControllerContainer.SelectorLabels,
				},
				Spec: v1.PodSpec{
					ServiceAccountName: cr.Spec.Security.APIServiceAccountName,
					SecurityContext:    cr.Spec.Security.PodSecurityContext,
					Containers:         containers,
					NodeSelector:       cr.Spec.NodeSelector,
					Affinity:           cr.Spec.Affinity,
					Tolerations:        cr.Spec.Tolerations,
					Volumes:            volumes,
				},
			},
		},
	}
}

// Observer
func BuildDeploymentForObserver(cr *apiv1.IntegrityShield) *appsv1.Deployment {
	labels := cr.Spec.MetaLabels

	volumes := []v1.Volume{
		EmptyDirVolume("tmp"),
	}
	if cr.Spec.OCIRegistryConfig.ManifestPullSecret != "" {
		volumes = append(volumes, SecretVolume("docker-creds", cr.Spec.OCIRegistryConfig.ManifestPullSecret))
	}

	servervolumemounts := []v1.VolumeMount{
		{
			MountPath: "/tmp",
			Name:      "tmp",
		},
	}
	if cr.Spec.OCIRegistryConfig.ManifestPullSecret != "" {
		servervolumemounts = append(servervolumemounts, v1.VolumeMount{
			MountPath: "/run/secrets/docker",
			Name:      "docker-creds",
			ReadOnly:  true,
		})
	}

	var image string
	if cr.Spec.Observer.Tag != "" {
		image = SetImageVersion(cr.Spec.Observer.Image, cr.Spec.Observer.Tag, cr.Spec.Observer.Name)
	} else {
		version := GetVersion(cr.Spec.Observer.Name)
		image = SetImageVersion(cr.Spec.Observer.Image, version, cr.Spec.Observer.Name)
	}

	env := []v1.EnvVar{
		{
			Name:  "POD_NAMESPACE",
			Value: cr.Namespace,
		},
		{
			Name:  "LOG_LEVEL",
			Value: cr.Spec.Observer.LogLevel,
		},
		{
			Name:  "REQUEST_HANDLER_CONFIG_KEY",
			Value: cr.Spec.RequestHandlerConfigKey,
		},
		{
			Name:  "REQUEST_HANDLER_CONFIG_NAME",
			Value: cr.Spec.RequestHandlerConfigName,
		},
		{
			Name:  "ENABLE_DETAIL_RESULT",
			Value: strconv.FormatBool(cr.Spec.Observer.ExportDetailResult),
		},
		{
			Name:  "OBSERVER_RESULT_CONFIG_NAME",
			Value: cr.Spec.Observer.ResultDetailConfigName,
		},
		{
			Name:  "OBSERVER_RESULT_CONFIG_KEY",
			Value: cr.Spec.Observer.ResultDetailConfigKey,
		},
		{
			Name:  "INTERVAL",
			Value: cr.Spec.Observer.Interval,
		},
		{
			Name:  "REKOR_SERVER",
			Value: cr.Spec.RekorServerConfig.URL,
		},
	}
	if cr.Spec.OCIRegistryConfig.ManifestPullSecret != "" {
		env = append(env, v1.EnvVar{
			Name:  "DOCKER_CONFIG",
			Value: "/run/secrets/docker",
		})
	}

	serverContainer := v1.Container{
		Name:            cr.Spec.Observer.Name,
		SecurityContext: cr.Spec.Observer.SecurityContext,
		Image:           image,
		ImagePullPolicy: cr.Spec.Observer.ImagePullPolicy,
		VolumeMounts:    servervolumemounts,
		Env:             env,
		Resources:       cr.Spec.Observer.Resources,
	}

	containers := []v1.Container{
		serverContainer,
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.Observer.Name,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       cr.Spec.MaxSurge,
					MaxUnavailable: cr.Spec.MaxUnavailable,
				},
			},
			Replicas: cr.Spec.ReplicaCount,
			Selector: &metav1.LabelSelector{
				MatchLabels: cr.Spec.Observer.SelectorLabels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: cr.Spec.Observer.SelectorLabels,
				},
				Spec: v1.PodSpec{
					ServiceAccountName: cr.Spec.Security.ObserverServiceAccountName,
					SecurityContext:    cr.Spec.Security.PodSecurityContext,
					Containers:         containers,
					NodeSelector:       cr.Spec.NodeSelector,
					Affinity:           cr.Spec.Affinity,
					Tolerations:        cr.Spec.Tolerations,
					Volumes:            volumes,
				},
			},
		},
	}
}

var int420Var int32 = 420

func SecretVolume(name, secretName string) v1.Volume {

	return v1.Volume{
		Name: name,
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName:  secretName,
				DefaultMode: &int420Var,
			},
		},
	}

}

func EmptyDirVolume(name string) v1.Volume {

	return v1.Volume{
		Name: name,
		VolumeSource: v1.VolumeSource{
			EmptyDir: &v1.EmptyDirVolumeSource{},
		},
	}
}

// EqualDeployments returns a Boolean
func EqualDeployments(expected *appsv1.Deployment, found *appsv1.Deployment) bool {
	if !EqualLabels(found.ObjectMeta.Labels, expected.ObjectMeta.Labels) {
		return false
	}
	if !EqualPods(expected.Spec.Template, found.Spec.Template) {
		return false
	}
	return true
}

// EqualPods returns a Boolean
func EqualPods(expected v1.PodTemplateSpec, found v1.PodTemplateSpec) bool {
	if !EqualLabels(found.ObjectMeta.Labels, expected.ObjectMeta.Labels) {
		return false
	}
	if !EqualAnnotations(found.ObjectMeta.Annotations, expected.ObjectMeta.Annotations) {
		return false
	}
	if !reflect.DeepEqual(found.Spec.ServiceAccountName, expected.Spec.ServiceAccountName) {
		return false
	}
	if len(found.Spec.Containers) != len(expected.Spec.Containers) {
		return false
	}
	if !EqualContainers(expected.Spec.Containers[0], found.Spec.Containers[0]) {
		return false
	}
	return true
}

// EqualContainers returns a Boolean
func EqualContainers(expected v1.Container, found v1.Container) bool {
	if !reflect.DeepEqual(found.Name, expected.Name) {
		return false
	}
	if !reflect.DeepEqual(found.Image, expected.Image) {
		return false
	}
	if !reflect.DeepEqual(found.ImagePullPolicy, expected.ImagePullPolicy) {
		return false
	}
	if !reflect.DeepEqual(found.VolumeMounts, expected.VolumeMounts) {
		return false
	}
	if !reflect.DeepEqual(found.SecurityContext, expected.SecurityContext) {
		return false
	}
	if !reflect.DeepEqual(found.Ports, expected.Ports) {
		return false
	}
	if !reflect.DeepEqual(found.Args, expected.Args) {
		return false
	}
	if !reflect.DeepEqual(found.Env, expected.Env) {
		return false
	}
	return true
}

func EqualLabels(found map[string]string, expected map[string]string) bool {
	return reflect.DeepEqual(found, expected)
}

func EqualAnnotations(found map[string]string, expected map[string]string) bool {
	return reflect.DeepEqual(found, expected)
}

func GetVersion(name string) string {
	reqLogger := log.WithValues("BuildDeployment", name)
	var version string
	var tmpCsv map[string]interface{}
	fpath := filepath.Clean(apiv1.CsvPath)
	tmpBytes, err := ioutil.ReadFile(fpath)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("failed to read csv file `%s`", fpath))
	}

	_ = yaml.Unmarshal(tmpBytes, &tmpCsv)

	// spec.version
	spec, ok := tmpCsv["spec"].(map[string]interface{})
	if !ok {
		reqLogger.Error(err, "failed to get spec from csv")
	}
	version, ok = spec["version"].(string)
	if !ok {
		reqLogger.Error(err, "failed to get version from csv")
	}
	return version
}

func SetImageVersion(image, version, name string) string {
	reqLogger := log.WithValues("BuildDeployment", name)
	// specify registry
	slice := strings.Split(image, "/")
	tmpImage := slice[len(slice)-1]
	registry := strings.Replace(image, tmpImage, "", 1)
	// specify image name (remove tag if image contains tag)
	var img string
	if strings.Contains(tmpImage, ":") {
		reqLogger.Info(fmt.Sprintf("Image version should be deinfed in the 'imageTag' field. %s", image))
		slice = strings.Split(tmpImage, ":")
		img = slice[0]
	} else {
		img = tmpImage
	}
	imgVersion := fmt.Sprintf("%s%s:%s", registry, img, version)
	return imgVersion
}
