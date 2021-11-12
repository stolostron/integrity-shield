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

var _ = Describe("Test: integrity shield", func() {
	Describe("Test: integrity shield operator", func() {
		It("Operator Pod should be Running Status", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := "integrity-shield-operator-controller-manager"
			Eventually(func() error {
				return CheckPodStatus(framework, ishield_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test: ishield api and gatekeeper", func() {
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
		It("IShield server should be created properly", func() {
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
	Describe("Test: validating request by ishield api server and gatekeeper", func() {
		It("Constraint can be created", func() {
			var timeout int = 120
			expected := constraint_name
			cmd_err := Kubectl("create", "-f", constraint)
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
			expected := test_configmap_name_no_sign
			cmd_err := Kubectl("apply", "-f", test_configmap_no_sign, "-n", test_namespace)
			Expect(cmd_err).NotTo(BeNil())
			Eventually(func() error {
				return CheckBlockEvent(framework, "Deny", test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Request with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_configmap_name_annotation
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_configmap_annotation_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Request defined in ObjectSelector can be created after validation", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_configmap_name_inscope
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_configmap_inscope, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Request defined in SkipObjects can be created without signature", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_configmap_name_skip
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_configmap_skip, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Prepare for detect mode test", func() {
			var timeout int = 120
			expected := constraint_name
			By("Deleting constraint")
			cmd_err := Kubectl("delete", "-f", constraint)
			Expect(cmd_err).To(BeNil())
			By("Creating constraint for detection mode")
			cmd_err = Kubectl("create", "-f", constraint_detect)
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
			expected := test_configmap_name_no_sign
			cmd_err := Kubectl("apply", "-f", test_configmap_no_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test: ishield api and gatekeeper: delete", func() {
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
	Describe("Test: ishield api and admission controller", func() {
		It("Clearing test-ns", func() {
			By("Deleting test_configmap_skip")
			cmd_err := Kubectl("delete", "-f", test_configmap_skip, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			By("Deleting test_configmap_inscope")
			cmd_err = Kubectl("delete", "-f", test_configmap_inscope, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			By("Deleting test_configmap_annotation_sign")
			cmd_err = Kubectl("delete", "-f", test_configmap_annotation_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			By("Deleting test_configmap_no_sign")
			cmd_err = Kubectl("delete", "-f", test_configmap_no_sign, "-n", test_namespace)
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
	Describe("Test: validating request by admission controller", func() {
		It("ManifestIntegrityProfile can be created", func() {
			var timeout int = 120
			expected := constraint_name
			cmd_err := Kubectl("create", "-f", constraint_ac)
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
			expected := test_configmap_name_no_sign
			cmd_err := Kubectl("apply", "-f", test_configmap_no_sign, "-n", test_namespace)
			Expect(cmd_err).NotTo(BeNil())
			Eventually(func() error {
				return CheckBlockEvent(framework, "Deny", test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Request with valid signature should be allowed", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := test_configmap_name_annotation
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_configmap_annotation_sign, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test: ishield api and admission controller: delete", func() {
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
