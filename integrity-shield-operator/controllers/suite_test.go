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

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghodss/yaml"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apisv1alpha1 "github.com/IBM/integrity-enforcer/integrity-shield-operator/api/v1alpha1"
	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-shield-operator/api/v1alpha1"
	rs "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesignature/v1alpha1"
	rsp "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	ec "github.com/IBM/integrity-enforcer/shield/pkg/apis/shieldconfig/v1alpha1"
	sigconf "github.com/IBM/integrity-enforcer/shield/pkg/apis/signerconfig/v1alpha1"
	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	scc "github.com/openshift/api/security/v1"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	// +kubebuilder:scaffold:imports
)

const testIShieldCRDPath = "../config/crd/bases/apis.integrityshield.io_integrityshields.yaml"
const testIShieldCRPath = "../resources/default-ishield-cr.yaml"
const iShieldNamespace = "integrity-shield-operator-system"

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment
var scheme *runtime.Scheme
var r *IntegrityShieldReconciler
var iShieldCR *apisv1alpha1.IntegrityShield
var crBytes []byte

// Kubectl executes kubectl commands
func Kubectl(args ...string) error {
	cmd := exec.Command("kubectl", args...)
	err := cmd.Start()
	if err != nil {
		Fail(fmt.Sprintf("Error: %v", err))
	}
	err_w := cmd.Wait()
	return err_w
}

func getTestIShieldCRPath() string {
	pwd, err := os.Getwd()
	if err != nil {
		pwd = "./"
	}
	return filepath.Join(pwd, testIShieldCRPath)
}

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

func embedRSP(cr *apisv1alpha1.IntegrityShield) *apisv1alpha1.IntegrityShield {
	secretPattern := common.RulePattern("Secret")
	cr.Spec.ResourceSigningProfiles = []*apiv1alpha1.ProfileConfig{
		{
			Name: "sample-rsp",
			ResourceSigningProfileSpec: &rsp.ResourceSigningProfileSpec{
				TargetNamespaceSelector: &common.NamespaceSelector{
					Include: []string{"test-other-ns"},
				},
				ProtectRules: []*common.Rule{
					{
						Match: []*common.RequestPattern{
							{
								Kind: &secretPattern,
							},
						},
					},
				},
			},
		},
	}
	return cr
}

var _ = BeforeSuite(func(done Done) {
	logf.SetLogger(zap.New())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	scheme = runtime.NewScheme()
	err = apisv1alpha1.AddToScheme(scheme)
	err = clientgoscheme.AddToScheme(scheme)
	err = apiextensionsv1.AddToScheme(scheme)
	err = apiextensionsv1beta1.AddToScheme(scheme)

	err = apisv1alpha1.AddToScheme(scheme)
	err = scc.AddToScheme(scheme)
	err = ec.AddToScheme(scheme)
	err = rsp.AddToScheme(scheme)
	err = rs.AddToScheme(scheme)
	err = sigconf.AddToScheme(scheme)

	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sClient).ToNot(BeNil())

	ctx := context.Background()

	// create ns
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: iShieldNamespace}}
	_ = k8sClient.Create(ctx, ns)

	// create ishield cr
	var defaultCR *apisv1alpha1.IntegrityShield
	crBytes, err = ioutil.ReadFile(testIShieldCRPath)
	Expect(err).Should(BeNil())
	err = yaml.Unmarshal(crBytes, &defaultCR)
	Expect(err).Should(BeNil())
	defaultCR.SetNamespace(iShieldNamespace)
	defaultCR = embedRSP(defaultCR)
	_ = k8sClient.Create(ctx, defaultCR)
	iShieldCR = &apisv1alpha1.IntegrityShield{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: defaultCR.Name, Namespace: defaultCR.Namespace}, iShieldCR)
	Expect(err).Should(BeNil())

	r = &IntegrityShieldReconciler{
		Client: k8sClient,
		Log:    ctrl.Log.WithName("controllers").WithName("IntegrityShield"),
		Scheme: scheme,
	}

	keyringSecretName := "keyring-secret"
	emptyKeyring := &v1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: iShieldCR.Namespace, Name: keyringSecretName}, Data: map[string][]byte{}}
	_ = k8sClient.Create(ctx, emptyKeyring)

	close(done)
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})

func doReconcileTest(fn func(*apiv1alpha1.IntegrityShield) (ctrl.Result, error), timeout int) {
	// Reconcile - Create
	Eventually(func() error {
		result, err := fn(iShieldCR)
		if err != nil {
			r.Log.Info(err.Error())
			return err
		}
		resultBytes, _ := json.Marshal(result)
		if !result.Requeue {
			r.Log.Info(fmt.Sprintf("Result: %s", string(resultBytes)))
			return fmt.Errorf("Reconcile Result: %s", string(resultBytes))
		}
		return nil
	}, timeout, 1).Should(BeNil())
	// Reconcile - AlreadyExists
	Eventually(func() error {
		result, err := fn(iShieldCR)
		if err != nil {
			r.Log.Info(err.Error())
			return err
		}
		resultBytes, _ := json.Marshal(result)
		if result.Requeue {
			r.Log.Info(fmt.Sprintf("Result: %s", string(resultBytes)))
			return fmt.Errorf("Reconcile Result: %s", string(resultBytes))
		}
		return nil
	}, timeout, 1).Should(BeNil())

}

var _ = Describe("Test integrity shield", func() {

	It("repeating Reconcile() Test", func() {
		req := reconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: iShieldCR.Namespace, Name: iShieldCR.Name},
		}

		i := 0
		maxReconcileTrial := 600
		deployFound := &appsv1.Deployment{}
		for {
			_, recError := r.Reconcile(context.Background(), req)
			i++

			if i%10 == 0 {
				fmt.Println("[DEBUG] reconcile iteration: ", i)
				tmpErr := k8sClient.Get(context.Background(), types.NamespacedName{Name: iShieldCR.GetIShieldServerDeploymentName(), Namespace: iShieldNamespace}, deployFound)
				if tmpErr == nil {
					break
				}
			}
			if i > maxReconcileTrial {
				fmt.Println("[DEBUG] reconcile iteration exceeded the max trial num, but ishield server has not been deplyed.")
				tmpErr := fmt.Errorf("Reconcile Test exceeded the max trial number. The last error from reconcile(): %s", recError.Error())
				Expect(tmpErr).Should(BeNil())
			}
			time.Sleep(time.Millisecond * 500)
		}
		fmt.Println("[DEBUG] reconcile finished: ", i)
	})

	It("IShiled CR delete & re-create Test", func() {
		ctx := context.Background()
		var err error
		_ = k8sClient.Delete(ctx, iShieldCR)
		time.Sleep(time.Second * 10)

		var newIShieldCR *apiv1alpha1.IntegrityShield
		err = yaml.Unmarshal(crBytes, &newIShieldCR)
		Expect(err).Should(BeNil())
		newIShieldCR.SetNamespace(iShieldNamespace)
		newIShieldCR = embedRSP(newIShieldCR)
		err = k8sClient.Create(ctx, newIShieldCR)
		Expect(err).Should(BeNil())
		iShieldCR = &apisv1alpha1.IntegrityShield{}
		err = k8sClient.Get(ctx, types.NamespacedName{Name: newIShieldCR.Name, Namespace: newIShieldCR.Namespace}, iShieldCR)
		Expect(err).Should(BeNil())
	})

	It("Util Func isDeploymentAvailable() Test", func() {
		_ = r.isDeploymentAvailable(iShieldCR)
	})
	It("Reconcile func createOrUpdateWebhook() Test", func() {
		_, _ = r.createOrUpdateWebhook(iShieldCR)
	})
	It("Util Func deleteWebhook() Test", func() {
		_, _ = r.deleteWebhook(iShieldCR)
	})

})
