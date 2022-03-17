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
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo" //nolint:golint
	. "github.com/onsi/gomega" //nolint:golint
)

var _ = Describe("Test: Integrity Shield", func() {
	Describe("Test1: Integrity Shield Operator", func() {
		It("Operator Pod should be Running Status", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := "integrity-shield-operator-controller-manager"
			Eventually(func() error {
				return CheckPodStatus(framework, ishield_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test2: Integrity Shield API and Gatekeeper", func() {
		It("Gatekeeper should be running on the cluster", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := "gatekeeper-controller-manager"
			namespace := gatekeeper_ns
			if ishield_env == "remote" {
				namespace = gatekeeper_ocp_ns
			}
			Eventually(func() error {
				return CheckPodStatus(framework, namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("IShield API Pod should be created properly", func() {
			framework := initFrameWork()
			var timeout int = 300
			expected := api_name
			cmd_err := Kubectl("apply", "-f", integrityShieldOperatorCR_gk, "-n", ishield_namespace)
			if cmd_err != nil {
				fmt.Printf("Error while creating CR; %s\n", cmd_err.Error())
				if exitError, ok := cmd_err.(*exec.ExitError); ok {
					fmt.Printf("stderr: %s\n", string(exitError.Stderr))
				}
			}
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckPodStatus(framework, ishield_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Observer should be created properly", func() {
			framework := initFrameWork()
			var timeout int = 300
			expected := observer_name
			Eventually(func() error {
				return CheckPodStatus(framework, ishield_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("IShield resources should be created properly", func() {
			framework := initFrameWork()
			time.Sleep(time.Second * 30)
			By("Check created ishield resources...")
			for _, iShieldRes := range ishield_resource_list_gk {
				fmt.Print("Namespace: ", iShieldRes.Namespace, " Kind: ", iShieldRes.Kind, " Name: ", iShieldRes.Name, "\n")
				err := CheckIShieldResources(framework, iShieldRes.Kind, iShieldRes.Namespace, iShieldRes.Name)
				Expect(err).To(BeNil())
			}
		})
	})
	Describe("Test3: RequestHandlerConfig and ManifestVerifyRule", func() {
		It("Constraint can be created", func() {
			var timeout int = 120
			expected := constraint_name
			cmd_err := Kubectl("create", "-f", constraint_test3)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				err := Kubectl("get", "constraint", expected)
				if err != nil {
					return err
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
		It("Request without signature should be blocked", func() {
			time.Sleep(time.Second * 30)
			framework := initFrameWork()
			var timeout int = 120
			expected := test_cm_name_no_sign
			cmd_err := Kubectl("apply", "-f", test_cm_no_sign, "-n", test_namespace)
			Expect(cmd_err).NotTo(BeNil())
			Eventually(func() error {
				return CheckBlockEvent(framework, "Deny", test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Request with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_cm_name_annotation
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_cm_annotation_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Request defined in ObjectSelector can be created after validation", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_cm_name_inscope
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_cm_inscope, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Request defined in SkipObjects can be created without signature", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_cm_name_skip
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_cm_skip, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Prepare for read-only-file-system test", func() {
			var timeout int = 120
			expected := constraint_name_secret
			By("Deleting constraint")
			cmd_err := Kubectl("delete", "-f", constraint_test3)
			Expect(cmd_err).To(BeNil())
			By("Deleting configmap")
			cmd_err = Kubectl("delete", "-f", test_cm_annotation_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			By("Creating constraint for mount:false mode")
			cmd_err = Kubectl("create", "-f", constraint_test3_secret)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				err := Kubectl("get", "constraint", expected)
				if err != nil {
					return err
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
		It("Request with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_cm_name_annotation
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_cm_annotation_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Prepare for a test using public key attached to constraint", func() {
			var timeout int = 120
			expected := constraint_name_key
			By("Deleting constraint")
			cmd_err := Kubectl("delete", "-f", constraint_test3_secret)
			Expect(cmd_err).To(BeNil())
			By("Deleting configmap")
			cmd_err = Kubectl("delete", "-f", test_cm_annotation_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			By("Creating constraint containing PEM encoded public key")
			cmd_err = Kubectl("create", "-f", constraint_test3_key)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				err := Kubectl("get", "constraint", expected)
				if err != nil {
					return err
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
		It("Request with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_cm_name_annotation
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_cm_annotation_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Prepare for detect mode test", func() {
			var timeout int = 120
			expected := constraint_name
			By("Deleting constraint")
			cmd_err := Kubectl("delete", "-f", constraint_test3_key)
			Expect(cmd_err).To(BeNil())
			By("Creating constraint for inform mode")
			cmd_err = Kubectl("create", "-f", constraint_test3_inform)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				err := Kubectl("get", "constraint", expected)
				if err != nil {
					return err
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
		It("Request without signature can be created if enforce mode is disabled", func() {
			time.Sleep(time.Second * 30)
			framework := initFrameWork()
			var timeout int = 120
			expected := test_cm_name_no_sign
			cmd_err := Kubectl("apply", "-f", test_cm_no_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test4: Default Kubernetes Resource Verification", func() {
		It("Prepare for default k8s resource verification test", func() {
			By("Deleting constraint")
			cmd_err := Kubectl("delete", "-f", constraint_test3_inform)
			Expect(cmd_err).To(BeNil())
		})
		It("Constraint can be created", func() {
			var timeout int = 120
			expected := constraint_name_test4
			cmd_err := Kubectl("create", "-f", constraint_test4)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				err := Kubectl("get", "constraint", expected)
				if err != nil {
					return err
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
		It("Secret with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_secret_name
			By("Creating test Secret in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_secret, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckSecret(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		// It("CRD with valid signature should be allowed", func() {
		// 	framework := initFrameWork()
		// 	var timeout int = 120
		// 	expected := test_crd_name
		// 	By("Creating test CRD")
		// 	cmd_err := Kubectl("apply", "-f", test_crd)
		// 	Expect(cmd_err).To(BeNil())
		// 	Eventually(func() error {
		// 		return CheckCRD(framework, expected)
		// 	}, timeout, 1).Should(BeNil())
		// })
		It("Role with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_role_name
			By("Creating test Role in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_role, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckRole(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("RoleBinding with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_rb_name
			By("Creating test RoleBinding in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_rb, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckRoleBinding(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("ClusterRole with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_cr_name
			By("Creating test ClusterRole")
			cmd_err := Kubectl("apply", "-f", test_cr)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckClusterRole(framework, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("ClusterRoleBinding with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_crb_name
			By("Creating test ClusterRoleBinding")
			cmd_err := Kubectl("apply", "-f", test_crb)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckClusterRoleBinding(framework, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("ServiceAccount with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_sa_name
			By("Creating test ServiceAccount in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_sa, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckServiceAccount(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Service with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_svc_name
			By("Creating test Service in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_svc, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckService(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Deployment with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_deployment_name
			By("Creating test Deployment in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_deployment, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckDeployment(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test5: Integrity Shield API and Gatekeeper: Delete", func() {
		It("API and ishield resources should be deleted properly", func() {
			framework := initFrameWork()
			api_name := api_name
			api := GetPodName(framework, ishield_namespace, api_name)
			err, serverLog := KubectlOut("logs", "-n", ishield_namespace, api, "-c", "integrity-shield-api")
			Expect(err).To(BeNil())
			_ = ioutil.WriteFile("./e2etest-api.log", []byte(serverLog), 0640) // NO SONAR

			By("Server should be deleted properly")
			var timeout int = 300
			expected := api_name
			cmd_err := Kubectl("delete", "-f", integrityShieldOperatorCR_gk, "-n", ishield_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckPodStatus(framework, ishield_namespace, expected)
			}, timeout, 1).ShouldNot(BeNil())
			By("IShield resources should be deleted properly")
			time.Sleep(time.Second * 30)
			for _, iShieldRes := range ishield_resource_list_gk {
				fmt.Print(iShieldRes.Kind, " : ", iShieldRes.Name, "\n")
				err := CheckIShieldResources(framework, iShieldRes.Kind, iShieldRes.Namespace, iShieldRes.Name)
				if err == nil {
					fmt.Println("[DEBUG1] ", iShieldRes.Kind, " : ", iShieldRes.Name)
				} else {
					fmt.Println("[DEBUG2] ", iShieldRes.Kind, " : ", iShieldRes.Name, ", err: ", err.Error())
				}
				// Expect(err).NotTo(BeNil())
			}
		})
	})

	// admission controller mode
	Describe("Test6: Integrity Shield API and Admission Controller", func() {
		It("Clearing test-ns", func() {
			By("Deleting test_configmap_skip")
			cmd_err := Kubectl("delete", "-f", test_cm_skip, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			By("Deleting test_configmap_inscope")
			cmd_err = Kubectl("delete", "-f", test_cm_inscope, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			By("Deleting test_configmap_annotation_sign")
			cmd_err = Kubectl("delete", "-f", test_cm_annotation_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			By("Deleting test_cm_no_sign")
			cmd_err = Kubectl("delete", "-f", test_cm_no_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
		})
		It("IShield should be created properly", func() {
			framework := initFrameWork()
			var timeout int = 300
			expected := ac_server_name
			cmd_err := Kubectl("apply", "-f", integrityShieldOperatorCR_ac, "-n", ishield_namespace)
			if cmd_err != nil {
				fmt.Printf("Error while creating CR; %s\n", cmd_err.Error())
				if exitError, ok := cmd_err.(*exec.ExitError); ok {
					fmt.Printf("stderr: %s\n", string(exitError.Stderr))
				}
			}
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckPodStatus(framework, ishield_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("IShield resources should be created properly", func() {
			framework := initFrameWork()
			time.Sleep(time.Second * 30)
			By("Check created ishield resources...")
			for _, iShieldRes := range ishield_resource_list_ac {
				fmt.Print("Namespace: ", iShieldRes.Namespace, " Kind: ", iShieldRes.Kind, " Name: ", iShieldRes.Name, "\n")
				err := CheckIShieldResources(framework, iShieldRes.Kind, iShieldRes.Namespace, iShieldRes.Name)
				Expect(err).To(BeNil())
			}
		})
	})
	Describe("Test7: Validating Request based on ManifestIntegrityProfile", func() {
		It("ManifestIntegrityProfile can be created", func() {
			var timeout int = 120
			expected := constraint_name
			cmd_err := Kubectl("create", "-f", constraint_test7)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				err := Kubectl("get", "mip", expected)
				if err != nil {
					return err
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
		It("Request without siganture should be blocked", func() {
			time.Sleep(time.Second * 30)
			framework := initFrameWork()
			var timeout int = 120
			expected := test_cm_name_no_sign
			cmd_err := Kubectl("apply", "-f", test_cm_no_sign, "-n", test_namespace)
			Expect(cmd_err).NotTo(BeNil())
			Eventually(func() error {
				return CheckBlockEvent(framework, "Deny", test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Request with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_cm_name_annotation
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_cm_annotation_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test8: Integrity Shield API and Admission Controller: Delete", func() {
		It("API and ishield resources should be deleted properly", func() {
			framework := initFrameWork()
			ac_server_name := ac_server_name
			ac_server := GetPodName(framework, ishield_namespace, ac_server_name)
			err, serverLog := KubectlOut("logs", "-n", ishield_namespace, ac_server, "-c", "integrity-shield-validator")
			Expect(err).To(BeNil())
			_ = ioutil.WriteFile("./e2etest-ac-server.log", []byte(serverLog), 0640) // NO SONAR

			By("Server should be deleted properly")
			var timeout int = 300
			expected := ac_server_name
			cmd_err := Kubectl("delete", "-f", integrityShieldOperatorCR_ac, "-n", ishield_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckPodStatus(framework, ishield_namespace, expected)
			}, timeout, 1).ShouldNot(BeNil())
			By("IShield resources should be deleted properly")
			time.Sleep(time.Second * 30)
			for _, iShieldRes := range ishield_resource_list_gk {
				fmt.Print(iShieldRes.Kind, " : ", iShieldRes.Name, "\n")
				err := CheckIShieldResources(framework, iShieldRes.Kind, iShieldRes.Namespace, iShieldRes.Name)
				if err == nil {
					fmt.Println("[DEBUG1] ", iShieldRes.Kind, " : ", iShieldRes.Name)
				} else {
					fmt.Println("[DEBUG2] ", iShieldRes.Kind, " : ", iShieldRes.Name, ", err: ", err.Error())
				}
				// Expect(err).NotTo(BeNil())
			}
		})
	})

})
