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
	"fmt"
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo" //nolint:golint
	mipclient "github.com/stolostron/integrity-shield/webhook/admission-controller/pkg/client/manifestintegrityprofile/clientset/versioned/typed/manifestintegrityprofile/v1"
	v1 "k8s.io/api/core/v1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"

	// "k8s.io/client-go/tools/events"
	"k8s.io/klog"
)

var (
	// kubeconfigPath    = os.Getenv("KUBECONFIG")
	// local_test, _                = strconv.ParseBool(os.Getenv("TEST_LOCAL"))
	kubeconfig_user                = os.Getenv("KUBE_CONTEXT_USERNAME")
	ishield_namespace              = os.Getenv("ISHIELD_NS")
	ishield_env                    = os.Getenv("ISHIELD_TEST_ENV")
	test_namespace                 = "test-ns"
	shield_dir                     = os.Getenv("SHIELD_OP_DIR")
	deploy_dir                     = shield_dir + "/test/deploy/"
	kubeconfigManaged              = os.Getenv("KUBECONFIG")
	tmpDir                         = os.Getenv("TMP_DIR")
	integrityShieldOperatorCR_gk   = tmpDir + "apis_v1_integrityshield.yaml"
	integrityShieldOperatorCR_ac   = tmpDir + "apis_v1_integrityshield_ac.yaml"
	api_name                       = "integrity-shield-api"
	observer_name                  = "integrity-shield-observer"
	ac_server_name                 = "integrity-shield-validator"
	constraint                     = deploy_dir + "test-manifest-integrity-constraint.yaml"
	constraint_readOnly            = deploy_dir + "test-manifest-integrity-constraint-keyconfig-secret.yaml"
	constraint_pem                 = deploy_dir + "test-manifest-integrity-constraint-keyconfig-key.yaml"
	constraint_detect              = deploy_dir + "test-manifest-integrity-constraint-inform.yaml"
	constraint_ac                  = deploy_dir + "test-manifest-integrity-profile.yaml"
	constraint_name                = "configmap-constraint"
	constraint_name_readOnly       = "configmap-constraint-keyconfig-secret"
	constraint_name_pem            = "configmap-constraint-keyconfig-pem"
	gatekeeper_ns                  = "gatekeeper-system"
	gatekeeper_ocp_ns              = "openshift-gatekeeper-system"
	test_configmap_name_no_sign    = "test-configmap-no-sign"
	test_configmap_name_annotation = "test-configmap-annotation"
	test_configmap_name_skip       = "test-configmap-skip"
	test_configmap_name_inscope    = "test-configmap-inscope"
	test_configmap_no_sign         = deploy_dir + "test-configmap-no-sign.yaml"
	test_configmap_annotation_sign = deploy_dir + "test-configmap-pgp-annotation.yaml"
	test_configmap_inscope         = deploy_dir + "test-configmap-inscope.yaml"
	test_configmap_skip            = deploy_dir + "test-configmap-skip.yaml"
)

var ishield_resource_list_gk = []ResourceRef{
	{
		Namespace:  ishield_namespace,
		Name:       "request-handler-config",
		Kind:       "ConfigMap",
		ApiVersion: "",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-sa",
		Kind:       "ServiceAccount",
		ApiVersion: "v1",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-api",
		Kind:       "Deployment",
		ApiVersion: "apps/v1",
	},
	{
		Name:       "manifestintegrityconstraint.constraints.gatekeeper.sh",
		Kind:       "CustomResourceDefinition",
		ApiVersion: " apiextensions.k8s.io/v1",
	},
	{
		Name:       "integrity-shield-role",
		Kind:       "ClusterRole",
		ApiVersion: "rbac.authorization.k8s.io/v1",
	},
	{
		Name:       "integrity-shield-rolebinding",
		Kind:       "ClusterRoleBinding",
		ApiVersion: "rbac.authorization.k8s.io/v1",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-role",
		Kind:       "Role",
		ApiVersion: "rbac.authorization.k8s.io/v1",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-rolebinding",
		Kind:       "RoleBinding",
		ApiVersion: "rbac.authorization.k8s.io/v1",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-api-tls",
		Kind:       "Secret",
		ApiVersion: "v1",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-api",
		Kind:       "Service",
		ApiVersion: "v1",
	},
	// {
	// 	Name:       "integrity-shield-psp",
	// 	Kind:       "PodSecurityPolicy",
	// 	ApiVersion: "policy/v1beta1",
	// },
}

var ishield_resource_list_ac = []ResourceRef{
	{
		Namespace:  ishield_namespace,
		Name:       "request-handler-config",
		Kind:       "ConfigMap",
		ApiVersion: "",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "admission-controller-config",
		Kind:       "ConfigMap",
		ApiVersion: "",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-sa",
		Kind:       "ServiceAccount",
		ApiVersion: "v1",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-validator",
		Kind:       "Deployment",
		ApiVersion: "apps/v1",
	},
	{
		Name:       "manifestintegrityprofiles.apis.integrityshield.io",
		Kind:       "CustomResourceDefinition",
		ApiVersion: " apiextensions.k8s.io/v1",
	},
	{
		Name:       "integrity-shield-role",
		Kind:       "ClusterRole",
		ApiVersion: "rbac.authorization.k8s.io/v1",
	},
	{
		Name:       "integrity-shield-rolebinding",
		Kind:       "ClusterRoleBinding",
		ApiVersion: "rbac.authorization.k8s.io/v1",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-role",
		Kind:       "Role",
		ApiVersion: "rbac.authorization.k8s.io/v1",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-rolebinding",
		Kind:       "RoleBinding",
		ApiVersion: "rbac.authorization.k8s.io/v1",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-validator-tls",
		Kind:       "Secret",
		ApiVersion: "v1",
	},
	{
		Namespace:  ishield_namespace,
		Name:       "integrity-shield-validator-service",
		Kind:       "Service",
		ApiVersion: "v1",
	},
}

type ResourceRef struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Kind       string `json:"kind"`
	ApiVersion string `json:"apiVersion"`
}

type Framework struct {
	BaseName string

	KubeConfig  string
	KubeContext string
	Kubectl     string

	// KubeClientConfig which was used to create the connection.
	KubeClientConfig *rest.Config

	// Kubernetes API clientsets
	KubeClientSet          kubernetes.Interface
	APIExtensionsClientSet apiextcs.Interface
	MIPClient              mipclient.ApisV1Interface

	// Namespace in which all test resources should reside
	Namespace *v1.Namespace
}

func initFrameWork() *Framework {
	framework := &Framework{
		KubeConfig: kubeconfigManaged,
	}
	kubeConfig, err := LoadConfig(framework.KubeConfig, framework.KubeContext)
	if err != nil {
		Fail("fail to set kubeconfig")
	}
	framework.KubeClientSet, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		Fail("fail to set KubeClientSet")

	}
	framework.APIExtensionsClientSet, err = apiextcs.NewForConfig(kubeConfig)
	if err != nil {
		Fail("fail to set APIExtensionsClientSet")
	}
	framework.MIPClient, err = mipclient.NewForConfig(kubeConfig)
	if err != nil {
		Fail("fail to set MIPClient")
	}

	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: ishield_namespace,
		},
	}
	framework.Namespace = ns
	return framework
}

func LoadConfig(config, context string) (*rest.Config, error) {
	c, err := RestclientConfig(config, context)
	if err != nil {
		return nil, err
	}
	return clientcmd.NewDefaultClientConfig(*c, &clientcmd.ConfigOverrides{}).ClientConfig()
}

func RestclientConfig(config, context string) (*clientcmdapi.Config, error) {
	if config == "" {
		return nil, fmt.Errorf("config file must be specified to load client config")
	}
	c, err := clientcmd.LoadFromFile(config)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err.Error())
	}
	if context != "" {
		c.CurrentContext = context
	}
	return c, nil
}
func Load(data []byte) (*clientcmdapi.Config, error) {
	config := clientcmdapi.NewConfig()
	// if there's no data in a file, return the default object instead of failing (DecodeInto reject empty input)
	if len(data) == 0 {
		return config, nil
	}
	decoded, _, err := clientcmdlatest.Codec.Decode(data, &schema.GroupVersionKind{Version: clientcmdlatest.Version, Kind: "Config"}, config)
	if err != nil {
		return nil, err
	}
	return decoded.(*clientcmdapi.Config), nil
}
func LoadFromFile(filename string) (*clientcmdapi.Config, error) {
	kubeconfigBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	config, err := Load(kubeconfigBytes)
	if err != nil {
		return nil, err
	}
	klog.V(6).Infoln("Config loaded from file: ", filename)

	// set LocationOfOrigin on every Cluster, User, and Context
	for key, obj := range config.AuthInfos {
		obj.LocationOfOrigin = filename
		config.AuthInfos[key] = obj
	}
	for key, obj := range config.Clusters {
		obj.LocationOfOrigin = filename
		config.Clusters[key] = obj
	}
	for key, obj := range config.Contexts {
		obj.LocationOfOrigin = filename
		config.Contexts[key] = obj
	}

	if config.AuthInfos == nil {
		config.AuthInfos = map[string]*clientcmdapi.AuthInfo{}
	}
	if config.Clusters == nil {
		config.Clusters = map[string]*clientcmdapi.Cluster{}
	}
	if config.Contexts == nil {
		config.Contexts = map[string]*clientcmdapi.Context{}
	}

	return config, nil
}
