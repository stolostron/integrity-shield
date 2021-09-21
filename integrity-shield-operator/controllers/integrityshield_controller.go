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
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	apisv1alpha1 "github.com/IBM/integrity-enforcer/integrity-shield-operator/api/v1alpha1"
	"github.com/IBM/integrity-enforcer/integrity-shield-operator/resources"
)

var log = logf.Log.WithName("controller_integrityshield")

// IntegrityShieldReconciler reconciles a IntegrityShield object
type IntegrityShieldReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core,resources=services;serviceaccounts;events;configmaps;secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apis.integrityshield.io,resources=integrityshields;integrityshields/finalizers;shieldconfigs;signerconfigs;resourcesigningprofiles;resourcesignatures;helmreleasemetadatas,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=*
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings;roles;rolebindings,verbs=*
// +kubebuilder:rbac:groups=policy,resources=podsecuritypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=*
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=*

func (r *IntegrityShieldReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := r.Log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)

	// Fetch the IntegrityShield instance
	instance := &apisv1alpha1.IntegrityShield{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	var recResult ctrl.Result
	var recErr error

	// apply default config if not ignored
	// this step is necessary to identify default resource names such as ishield-webhook-config, so this should be done even before finalizer
	if !instance.Spec.IgnoreDefaultIShieldCR {
		instance = resources.MergeDefaultIntegrityShieldCR(instance, "")
	}

	// Integrity Shield is under deletion - finalizer step
	if !instance.ObjectMeta.DeletionTimestamp.IsZero() {
		if containsString(instance.ObjectMeta.Finalizers, apisv1alpha1.CleanupFinalizerName) {
			if err := r.deleteClusterScopedChildrenResources(instance); err != nil {
				// if fail to delete the external dependency here, return with error
				// so that it can be retried
				reqLogger.Error(err, "Error occured during finalizer process. retrying soon.")
				return ctrl.Result{}, err
			}

			// remove our finalizer from the list and update it.
			instance.ObjectMeta.Finalizers = removeString(instance.ObjectMeta.Finalizers, apisv1alpha1.CleanupFinalizerName)
			if err := r.Update(context.Background(), instance); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// otherwise, normal reconcile

	if ok, nonReadyKey := r.isKeyRingReady(instance); !ok {
		reqLogger.Info(fmt.Sprintf("KeyRing secret \"%s\" does not exist. Skip reconciling.", nonReadyKey))
		return ctrl.Result{Requeue: true}, nil
	}

	// Custom Resource Definition (CRD)
	recResult, recErr = r.createOrUpdateShieldConfigCRD(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	recResult, recErr = r.createOrUpdateSignerConfigCRD(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	recResult, recErr = r.createOrUpdateResourceSignatureCRD(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	recResult, recErr = r.createOrUpdateResourceSigningProfileCRD(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	enabledPulgins := instance.Spec.ShieldConfig.GetEnabledPlugins()
	if enabledPulgins["helm"] {
		recResult, recErr = r.createOrUpdateHelmReleaseMetadataCRD(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	//Custom Resources (CR)
	recResult, recErr = r.createOrUpdateShieldConfigCR(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	recResult, recErr = r.createOrUpdateSignerConfigCR(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	if len(instance.Spec.ResourceSigningProfiles) > 0 {
		for _, prof := range instance.Spec.ResourceSigningProfiles {
			recResult, recErr = r.createOrUpdateResourceSigningProfileCR(instance, prof)
			if recErr != nil || recResult.Requeue {
				return recResult, recErr
			}
		}
	}

	//Secret
	recResult, recErr = r.createOrUpdateTlsSecret(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Service Account
	recResult, recErr = r.createOrUpdateServiceAccount(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Cluster Role
	recResult, recErr = r.createOrUpdateClusterRoleForIShield(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Cluster Role Binding
	recResult, recErr = r.createOrUpdateClusterRoleBindingForIShield(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Role
	recResult, recErr = r.createOrUpdateRoleForIShield(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Role Binding
	recResult, recErr = r.createOrUpdateRoleBindingForIShield(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	// ishield-admin
	if !instance.Spec.Security.AutoIShieldAdminCreationDisabled {
		//Cluster Role
		recResult, recErr = r.createOrUpdateClusterRoleForIShieldAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//Cluster Role Binding
		recResult, recErr = r.createOrUpdateClusterRoleBindingForIShieldAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//Role
		recResult, recErr = r.createOrUpdateRoleForIShieldAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//Role Binding
		recResult, recErr = r.createOrUpdateRoleBindingForIShieldAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	// Pod Security Policy (PSP)
	recResult, recErr = r.createOrUpdatePodSecurityPolicy(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Deployment
	recResult, recErr = r.createOrUpdateWebhookDeployment(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Service
	recResult, recErr = r.createOrUpdateWebhookService(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Webhook Configuration
	// wait until deployment is available
	if r.isDeploymentAvailable(instance) {
		recResult, recErr = r.createOrUpdateWebhook(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	} else {
		recResult, recErr = r.deleteWebhook(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	reqLogger.Info("Reconciliation successful!", "Name", instance.Name)
	// since we updated the status in the CR, sleep 5 seconds to allow the CR to be refreshed.
	time.Sleep(5 * time.Second)

	return ctrl.Result{}, nil
}

func (r *IntegrityShieldReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&apisv1alpha1.IntegrityShield{}).
		Owns(&apisv1alpha1.IntegrityShield{}).
		Complete(r)
}

func (r *IntegrityShieldReconciler) deleteClusterScopedChildrenResources(instance *apisv1alpha1.IntegrityShield) error {
	// delete any cluster scope resources owned by the instance
	// (In Iubernetes 1.20 and later, a garbage collector ignore cluster scope children even if their owner is deleted)
	var err error
	_, err = r.deleteWebhook(instance)
	if err != nil {
		return err
	}
	_, err = r.deletePodSecurityPolicy(instance)
	if err != nil {
		return err
	}
	if !instance.Spec.Security.AutoIShieldAdminCreationDisabled {
		_, err = r.deleteClusterRoleBindingForIShieldAdmin(instance)
		if err != nil {
			return err
		}
		_, err = r.deleteClusterRoleForIShieldAdmin(instance)
		if err != nil {
			return err
		}
	}
	_, err = r.deleteClusterRoleBindingForIShield(instance)
	if err != nil {
		return err
	}
	_, err = r.deleteClusterRoleForIShield(instance)
	if err != nil {
		return err
	}

	enabledPulgins := instance.Spec.ShieldConfig.GetEnabledPlugins()
	if enabledPulgins["helm"] {
		_, err = r.deleteHelmReleaseMetadataCRD(instance)
		if err != nil {
			return err
		}
	}

	_, err = r.deleteResourceSigningProfileCRD(instance)
	if err != nil {
		return err
	}

	_, err = r.deleteResourceSignatureCRD(instance)
	if err != nil {
		return err
	}

	_, err = r.deleteSignerConfigCRD(instance)
	if err != nil {
		return err
	}

	_, err = r.deleteShieldConfigCRD(instance)
	if err != nil {
		return err
	}

	return nil
}

// Helper functions to check and remove string from a slice of strings.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}
