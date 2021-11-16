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
	"time"

	"github.com/go-logr/logr"
	apiv1 "github.com/open-cluster-management/integrity-shield/integrity-shield-operator/api/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// IntegrityShieldReconciler reconciles a IntegrityShield object
type IntegrityShieldReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

var log = logf.Log.WithName("controller_integrityshield")

//+kubebuilder:rbac:groups=apis.integrityshield.io,resources=integrityshields,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apis.integrityshield.io,resources=integrityshields/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=apis.integrityshield.io,resources=integrityshields/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=services;serviceaccounts;events;configmaps;secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=*
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings;roles;rolebindings,verbs=*
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=*
// +kubebuilder:rbac:groups=templates.gatekeeper.sh,resources=constrainttemplates,verbs=get;list;watch;create;update;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the IntegrityShield object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.7.2/pkg/reconcile
func (r *IntegrityShieldReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := r.Log.WithValues("integrityshield", req.NamespacedName)

	// your logic here
	// Fetch the IntegrityShield instance
	instance := &apiv1.IntegrityShield{}
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

	// Integrity Shield is under deletion - finalizer step
	if !instance.ObjectMeta.DeletionTimestamp.IsZero() {
		if containsString(instance.ObjectMeta.Finalizers, apiv1.CleanupFinalizerName) {
			if err := r.deleteClusterScopedChildrenResources(instance); err != nil {
				// if fail to delete the external dependency here, return with error
				// so that it can be retried
				reqLogger.Error(err, "Error occured during finalizer process. retrying soon.")
				return ctrl.Result{}, err
			}

			// remove our finalizer from the list and update it.
			instance.ObjectMeta.Finalizers = removeString(instance.ObjectMeta.Finalizers, apiv1.CleanupFinalizerName)
			if err := r.Update(context.Background(), instance); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	//Pod Security Policy (PSP)
	// recResult, recErr = r.createOrUpdatePodSecurityPolicy(instance)
	// if recErr != nil || recResult.Requeue {
	// 	return recResult, recErr
	// }

	//Config
	recResult, recErr = r.createOrUpdateRequestHandlerConfig(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Service Account
	recResult, recErr = r.createOrUpdateIShieldApiServiceAccount(instance)
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

	//CRD
	recResult, recErr = r.createOrUpdateManifestIntegrityDecisionCRD(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	// Observer
	if instance.Spec.Observer.Enabled {
		//CRD
		recResult, recErr = r.createOrUpdateManifestIntegrityStateCRD(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
		//Service Account
		recResult, recErr = r.createOrUpdateObserverServiceAccount(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
		//Cluster Role
		recResult, recErr = r.createOrUpdateClusterRoleForObserver(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
		//Cluster Role Binding
		recResult, recErr = r.createOrUpdateClusterRoleBindingForObserver(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
		//Role
		recResult, recErr = r.createOrUpdateRoleForObserver(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
		//Role Binding
		recResult, recErr = r.createOrUpdateRoleBindingForObserver(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
		//Deployment
		recResult, recErr = r.createOrUpdateObserverDeployment(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	// Gatekeeper
	if instance.Spec.UseGatekeeper {
		// Shield API Secret
		recResult, recErr = r.createOrUpdateTlsSecret(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		// API Deployment
		recResult, recErr = r.createOrUpdateIShieldAPIDeployment(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		// API Service
		recResult, recErr = r.createOrUpdateAPIService(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
		if r.isGatekeeperAvailable(instance) {
			// Gatekeeper constraint template
			recResult, recErr = r.createOrUpdateConstraintTemplate(instance)
			if recErr != nil || recResult.Requeue {
				return recResult, recErr
			}
		} else {
			return ctrl.Result{Requeue: true}, nil
		}

	} else { // If use admission controller instead of Gatekeeper
		// CRD
		recResult, recErr = r.createOrUpdateManifestIntegrityProfileCRD(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
		// ac config
		recResult, recErr = r.createOrUpdateACConfig(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		// webhook secret
		recResult, recErr = r.createOrUpdateACTlsSecret(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		// webhook Deployment
		recResult, recErr = r.createOrUpdateAdmissionControllerDeployment(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		// webhook Service
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
	}

	reqLogger.Info("Reconciliation successful!", "Name", instance.Name)
	// since we updated the status in the CR, sleep 5 seconds to allow the CR to be refreshed.
	time.Sleep(5 * time.Second)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IntegrityShieldReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&apiv1.IntegrityShield{}).
		Complete(r)
}

func (r *IntegrityShieldReconciler) deleteClusterScopedChildrenResources(instance *apiv1.IntegrityShield) error {
	// delete any cluster scope resources owned by the instance
	// (In Iubernetes 1.20 and later, a garbage collector ignore cluster scope children even if their owner is deleted)
	var err error

	//Cluster Role
	_, err = r.deleteClusterRoleForIShield(instance)
	if err != nil {
		return err
	}
	//Cluster Role Binding
	_, err = r.deleteClusterRoleBindingForIShield(instance)
	if err != nil {
		return err
	}

	// CRD
	_, err = r.deleteManifestIntegrityDecisionCRD(instance)
	if err != nil {
		return err
	}

	if instance.Spec.UseGatekeeper {
		if r.isGatekeeperAvailable(instance) {
			_, err = r.deleteConstraintTemplate(instance)
			if err != nil {
				return err
			}
		}
	} else {
		_, err = r.deleteWebhook(instance)
		if err != nil {
			return err
		}
		// CRD
		_, err = r.deleteManifestIntegrityProfileCRD(instance)
		if err != nil {
			return err
		}
	}
	// _, err = r.deletePodSecurityPolicy(instance)
	// if err != nil {
	// 	return err
	// }

	if instance.Spec.Observer.Enabled {
		_, err = r.deleteClusterRoleForObserver(instance)
		if err != nil {
			return err
		}
		_, err = r.deleteClusterRoleBindingForObserver(instance)
		if err != nil {
			return err
		}
		_, err = r.deleteManifestIntegrityStateCRD(instance)
		if err != nil {
			return err
		}
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
