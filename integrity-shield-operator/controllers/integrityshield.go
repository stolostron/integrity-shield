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
	"reflect"
	"time"

	apiv1 "github.com/IBM/integrity-shield/integrity-shield-operator/api/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	cert "github.com/IBM/integrity-shield/integrity-shield-operator/cert"
	res "github.com/IBM/integrity-shield/integrity-shield-operator/resources"
	templatev1 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/**********************************************

				CRD

***********************************************/
func (r *IntegrityShieldReconciler) createOrUpdateCRD(instance *apiv1.IntegrityShield, expected *extv1.CustomResourceDefinition) (ctrl.Result, error) {
	ctx := context.Background()

	found := &extv1.CustomResourceDefinition{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"CRD.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If CRD does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: ""}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		if !reflect.DeepEqual(expected.Spec, found.Spec) {
			expected.ObjectMeta = found.ObjectMeta
			err = r.Update(ctx, expected)
			if err != nil {
				reqLogger.Error(err, "Failed to update the resource")
				return ctrl.Result{}, err
			}
		}
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityShieldReconciler) deleteCRD(instance *apiv1.IntegrityShield, expected *extv1.CustomResourceDefinition) (ctrl.Result, error) {
	ctx := context.Background()
	found := &extv1.CustomResourceDefinition{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"CustomResourceDefinition.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info(fmt.Sprintf("Deleting the IShield CustomResourceDefinition %s", expected.Name))
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("Failed to delete the IShield CustomResourceDefinition %s", expected.Name))
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if errors.IsNotFound(err) {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else {
		return ctrl.Result{}, err
	}

}

func (r *IntegrityShieldReconciler) createOrUpdateManifestIntegrityProfileCRD(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildManifestIntegrityProfileCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteManifestIntegrityProfileCRD(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildManifestIntegrityProfileCRD(instance)
	return r.deleteCRD(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateObserverResultCRD(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildObserverResultCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteObserverResultCRD(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildObserverResultCRD(instance)
	return r.deleteCRD(instance, expected)
}

/**********************************************

				ConfigMap

***********************************************/

func (r *IntegrityShieldReconciler) createOrUpdateConfigMap(instance *apiv1.IntegrityShield, expected *corev1.ConfigMap) (ctrl.Result, error) {
	ctx := context.Background()
	found := &corev1.ConfigMap{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ConfigMap.Namespace", expected.Namespace,
		"ConfigMap.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If CRD does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: expected.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}
	// else {
	// if !reflect.DeepEqual(expected.Data, found.Data) {
	// 	expected.ObjectMeta = found.ObjectMeta
	// 	err = r.Update(ctx, expected)
	// 	if err != nil {
	// 		reqLogger.Error(err, "Failed to update the resource")
	// 		return ctrl.Result{}, err
	// 	}
	// }
	// }

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityShieldReconciler) createOrUpdateRequestHandlerConfig(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildReqConfigForIShield(instance)
	return r.createOrUpdateConfigMap(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateACConfig(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildACConfigForIShield(instance)
	return r.createOrUpdateConfigMap(instance, expected)
}

/**********************************************

				Role

***********************************************/

func (r *IntegrityShieldReconciler) createOrUpdateServiceAccount(instance *apiv1.IntegrityShield, expected *corev1.ServiceAccount) (ctrl.Result, error) {
	ctx := context.Background()
	found := &corev1.ServiceAccount{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ServiceAccount.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityShieldReconciler) createOrUpdateClusterRole(instance *apiv1.IntegrityShield, expected *rbacv1.ClusterRole) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.ClusterRole{}

	reqLogger := r.Log.WithValues(
		"ClusterRole.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"ClusterRole.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityShieldReconciler) deleteClusterRole(instance *apiv1.IntegrityShield, expected *rbacv1.ClusterRole) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.ClusterRole{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ClusterRole.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info(fmt.Sprintf("Deleting the IShield ClusterRole %s", expected.Name))
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("Failed to delete the IShield ClusterRole %s", expected.Name))
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if errors.IsNotFound(err) {

		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else {
		return ctrl.Result{}, err
	}

}

func (r *IntegrityShieldReconciler) createOrUpdateClusterRoleBinding(instance *apiv1.IntegrityShield, expected *rbacv1.ClusterRoleBinding) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.ClusterRoleBinding{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"RoleBinding.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityShieldReconciler) deleteClusterRoleBinding(instance *apiv1.IntegrityShield, expected *rbacv1.ClusterRoleBinding) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.ClusterRoleBinding{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ClusterRoleBinding.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info(fmt.Sprintf("Deleting the IShield ClusterRoleBinding %s", expected.Name))
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("Failed to delete the IShield ClusterRoleBinding %s", expected.Name))
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if errors.IsNotFound(err) {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else {
		return ctrl.Result{}, err
	}

}

func (r *IntegrityShieldReconciler) createOrUpdateRole(instance *apiv1.IntegrityShield, expected *rbacv1.Role) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.Role{}

	reqLogger := r.Log.WithValues(
		"Role.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Role.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Namespace: instance.Namespace, Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityShieldReconciler) createOrUpdateRoleBinding(instance *apiv1.IntegrityShield, expected *rbacv1.RoleBinding) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.RoleBinding{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"RoleBinding.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Namespace: instance.Namespace, Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

// api sa
func (r *IntegrityShieldReconciler) createOrUpdateIShieldApiServiceAccount(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildServiceAccountForIShield(instance)
	return r.createOrUpdateServiceAccount(instance, expected)
}

// observer sa
func (r *IntegrityShieldReconciler) createOrUpdateObserverServiceAccount(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildServiceAccountForObserver(instance)
	return r.createOrUpdateServiceAccount(instance, expected)
}

// cluster role binding
func (r *IntegrityShieldReconciler) createOrUpdateClusterRoleBindingForIShield(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForIShield(instance)
	return r.createOrUpdateClusterRoleBinding(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteClusterRoleBindingForIShield(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForIShield(instance)
	return r.deleteClusterRoleBinding(instance, expected)
}

// cluster role binding - observer
func (r *IntegrityShieldReconciler) createOrUpdateClusterRoleBindingForObserver(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForObserver(instance)
	return r.createOrUpdateClusterRoleBinding(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteClusterRoleBindingForObserver(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForObserver(instance)
	return r.deleteClusterRoleBinding(instance, expected)
}

// cluster role
func (r *IntegrityShieldReconciler) createOrUpdateClusterRoleForIShield(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForIShield(instance)
	return r.createOrUpdateClusterRole(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteClusterRoleForIShield(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForIShield(instance)
	return r.deleteClusterRole(instance, expected)
}

// cluster role - observer
func (r *IntegrityShieldReconciler) createOrUpdateClusterRoleForObserver(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForObserver(instance)
	return r.createOrUpdateClusterRole(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteClusterRoleForObserver(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForObserver(instance)
	return r.deleteClusterRole(instance, expected)
}

// role binding
func (r *IntegrityShieldReconciler) createOrUpdateRoleBindingForIShield(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildRoleBindingForIShield(instance)
	return r.createOrUpdateRoleBinding(instance, expected)
}

// role binding - observer
func (r *IntegrityShieldReconciler) createOrUpdateRoleBindingForObserver(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildRoleBindingForObserver(instance)
	return r.createOrUpdateRoleBinding(instance, expected)
}

// role
func (r *IntegrityShieldReconciler) createOrUpdateRoleForIShield(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildRoleForIShield(instance)
	return r.createOrUpdateRole(instance, expected)
}

// role - observer
func (r *IntegrityShieldReconciler) createOrUpdateRoleForObserver(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildRoleForObserver(instance)
	return r.createOrUpdateRole(instance, expected)
}

// func (r *IntegrityShieldReconciler) createOrUpdatePodSecurityPolicy(instance *apiv1.IntegrityShield) (ctrl.Result, error) {
// 	ctx := context.Background()
// 	expected := res.BuildPodSecurityPolicy(instance)
// 	found := &policyv1.PodSecurityPolicy{}

// 	reqLogger := r.Log.WithValues(
// 		"Instance.Name", instance.Name,
// 		"PodSecurityPolicy.Name", expected.Name)

// 	// Set CR instance as the owner and controller
// 	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
// 	if err != nil {
// 		reqLogger.Error(err, "Failed to define expected resource")
// 		return ctrl.Result{}, err
// 	}

// 	// If PodSecurityPolicy does not exist, create it and requeue
// 	err = r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

// 	if err != nil && errors.IsNotFound(err) {
// 		reqLogger.Info("Creating a new resource")
// 		err = r.Create(ctx, expected)
// 		if err != nil && errors.IsAlreadyExists(err) {
// 			// Already exists from previous reconcile, requeue.
// 			reqLogger.Info("Skip reconcile: resource already exists")
// 			return ctrl.Result{Requeue: true}, nil
// 		} else if err != nil {
// 			reqLogger.Error(err, "Failed to create new resource")
// 			return ctrl.Result{}, err
// 		}
// 		// Created successfully - return and requeue
// 		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
// 	} else if err != nil {
// 		return ctrl.Result{}, err
// 	}

// 	// No extra validation

// 	// No reconcile was necessary
// 	return ctrl.Result{}, nil

// }

// delete ishield-psp
// func (r *IntegrityShieldReconciler) deletePodSecurityPolicy(instance *apiv1.IntegrityShield) (ctrl.Result, error) {
// 	ctx := context.Background()
// 	expected := res.BuildPodSecurityPolicy(instance)
// 	found := &policyv1.PodSecurityPolicy{}

// 	reqLogger := r.Log.WithValues(
// 		"Instance.Name", instance.Name,
// 		"PodSecurityPolicy.Name", expected.Name)

// 	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

// 	if err == nil {
// 		reqLogger.Info("Deleting the IShield PodSecurityPolicy")
// 		err = r.Delete(ctx, found)
// 		if err != nil {
// 			reqLogger.Error(err, "Failed to delete the IShield PodSecurityPolicy")
// 			return ctrl.Result{}, err
// 		}
// 		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
// 	} else if errors.IsNotFound(err) {
// 		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
// 	} else {
// 		return ctrl.Result{}, err
// 	}
// }

/**********************************************

				Secret

***********************************************/

func (r *IntegrityShieldReconciler) createOrUpdateSecret(instance *apiv1.IntegrityShield, expected *corev1.Secret) (ctrl.Result, error) {
	ctx := context.Background()
	found := &corev1.Secret{}

	reqLogger := r.Log.WithValues(
		"Secret.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Secret.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If CRD does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {

		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func addCertValues(instance *apiv1.IntegrityShield, expected *corev1.Secret, serviceName string) *corev1.Secret {
	reqLogger := log.WithValues(
		"Secret.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Secret.Name", expected.Name)

	// generate and put certs
	ca, tlsKey, tlsCert, err := cert.GenerateCert(serviceName, instance.Namespace)
	if err != nil {
		reqLogger.Error(err, "Failed to generate certs")
	}

	_, ok_tc := expected.Data["tls.crt"]
	_, ok_tk := expected.Data["tls.key"]
	_, ok_ca := expected.Data["ca.crt"]
	if ok_ca && ok_tc && ok_tk {
		expected.Data["tls.crt"] = tlsCert
		expected.Data["tls.key"] = tlsKey
		expected.Data["ca.crt"] = ca
	}
	return expected
}

// api
func (r *IntegrityShieldReconciler) createOrUpdateTlsSecret(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildTlsSecretForIShield(instance)
	expected = addCertValues(instance, expected, instance.Spec.ApiServiceName)
	return r.createOrUpdateSecret(instance, expected)
}

// webhook
func (r *IntegrityShieldReconciler) createOrUpdateACTlsSecret(
	instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildAPITlsSecretForIShield(instance)
	expected = addCertValues(instance, expected, instance.Spec.WebhookServiceName)
	return r.createOrUpdateSecret(instance, expected)
}

/**********************************************

				Deployment

***********************************************/
func (r *IntegrityShieldReconciler) createOrUpdateDeployment(instance *apiv1.IntegrityShield, expected *appsv1.Deployment) (ctrl.Result, error) {
	ctx := context.Background()
	found := &appsv1.Deployment{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"Deployment.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	} else if !res.EqualDeployments(expected, found) {
		// If spec is incorrect, update it and requeue
		found.ObjectMeta.Labels = expected.ObjectMeta.Labels
		found.Spec = expected.Spec
		err = r.Update(ctx, found)
		if err != nil {
			reqLogger.Error(err, "Failed to update Deployment", "Namespace", instance.Namespace, "Name", found.Name)
			return ctrl.Result{}, err
		}
		reqLogger.Info("Updating IntegrityShield Controller Deployment", "Deployment.Name", found.Name)
		// Spec updated - return and requeue
		return ctrl.Result{Requeue: true}, nil
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityShieldReconciler) createOrUpdateIShieldAPIDeployment(instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildDeploymentForIShieldAPI(instance)
	return r.createOrUpdateDeployment(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateAdmissionControllerDeployment(instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildDeploymentForAdmissionController(instance)
	return r.createOrUpdateDeployment(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateObserverDeployment(instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildDeploymentForObserver(instance)
	return r.createOrUpdateDeployment(instance, expected)
}

/**********************************************

				Service

***********************************************/
func (r *IntegrityShieldReconciler) createOrUpdateService(instance *apiv1.IntegrityShield, expected *corev1.Service) (ctrl.Result, error) {
	ctx := context.Background()
	found := &corev1.Service{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"Service.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil
}

func (r *IntegrityShieldReconciler) createOrUpdateWebhookService(instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildServiceForIShield(instance)
	return r.createOrUpdateService(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateAPIService(instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildAPIServiceForIShield(instance)
	return r.createOrUpdateService(instance, expected)
}

/**********************************************

				Webhook

***********************************************/

func (r *IntegrityShieldReconciler) createOrUpdateWebhook(instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildValidatingWebhookConfigurationForIShield(instance)
	found := &admregv1.ValidatingWebhookConfiguration{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ValidatingWebhookConfiguration.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		// locad cabundle
		secret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: instance.Spec.WebhookServerTlsSecretName, Namespace: instance.Namespace}, secret)
		if err != nil {
			reqLogger.Error(err, "Fail to load CABundle from Secret")
		}
		cabundle, ok := secret.Data["ca.crt"]
		if ok {
			expected.Webhooks[0].ClientConfig.CABundle = cabundle
		}

		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue

		reqLogger.Info("Webhook has been created.", "Name", instance.Name)
		evtName := "ishield-webhook-reconciled"
		_ = r.createOrUpdateWebhookEvent(instance, evtName, expected.Name)

		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

// delete webhookconfiguration
func (r *IntegrityShieldReconciler) deleteWebhook(instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildValidatingWebhookConfigurationForIShield(instance)
	found := &admregv1.ValidatingWebhookConfiguration{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ValidatingWebhookConfiguration.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info("Deleting the IShield webhook")
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, "Failed to delete the IShield Webhook")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if errors.IsNotFound(err) {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else {
		return ctrl.Result{}, err
	}
}

// wait function
func (r *IntegrityShieldReconciler) isDeploymentAvailable(instance *apiv1.IntegrityShield) bool {
	ctx := context.Background()
	found := &appsv1.Deployment{}
	expected := res.BuildDeploymentForAdmissionController(instance)
	// If Deployment does not exist, return false
	err := r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: expected.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		return false
	} else if err != nil {
		return false
	}

	// return true only if deployment is available
	if found.Status.AvailableReplicas > 0 {
		return true
	}

	return false
}

func (r *IntegrityShieldReconciler) createOrUpdateWebhookEvent(instance *apiv1.IntegrityShield, evtName, webhookName string) error {
	ctx := context.Background()
	evtNamespace := instance.Namespace
	involvedObject := corev1.ObjectReference{
		Namespace:  evtNamespace,
		APIVersion: instance.APIVersion,
		Kind:       instance.Kind,
		Name:       instance.Name,
	}
	now := time.Now()
	evtSourceName := "IntegrityShield"
	reason := "webhook-reconciled"
	msg := fmt.Sprintf("[IntegrityShieldEvent] IntegrityShield reconciled MutatingWebhookConfiguration \"%s\"", webhookName)
	expected := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      evtName,
			Namespace: evtNamespace,
			Annotations: map[string]string{
				"integrityshield.io/eventType": "integrityshield.io/eventType",
			},
		},
		InvolvedObject:      involvedObject,
		Type:                evtSourceName,
		Source:              corev1.EventSource{Component: evtSourceName},
		ReportingController: evtSourceName,
		ReportingInstance:   evtName,
		Action:              evtName,
		FirstTimestamp:      metav1.NewTime(now),
		LastTimestamp:       metav1.NewTime(now),
		EventTime:           metav1.NewMicroTime(now),
		Message:             msg,
		Reason:              reason,
		Count:               1,
	}
	found := &corev1.Event{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"Event.Name", expected.Name)

	// If Event does not exist, create it and requeue
	err := r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: expected.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new event")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip creating event: resource already exists")
			return nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new event")
			return err
		}
		// Created successfully - return and requeue
		return nil
	} else if err != nil {
		return err
	} else {
		// Update Event
		found.Count = found.Count + 1
		found.EventTime = metav1.NewMicroTime(now)
		found.LastTimestamp = metav1.NewTime(now)
		found.Message = msg
		found.Reason = reason
		found.ReportingController = evtSourceName
		found.ReportingInstance = evtName

		err = r.Update(ctx, found)
		if err != nil {
			reqLogger.Error(err, "Failed to update Event", "Namespace", instance.Namespace, "Name", found.Name)
			return err
		}
		reqLogger.Info("Updated Event", "Deployment.Name", found.Name)
		// Spec updated - return and requeue
		return nil
	}
}

/**********************************************

			Gatekeeper Constraint

***********************************************/

func (r *IntegrityShieldReconciler) createOrUpdateConstraintTemplate(instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	ctx := context.Background()
	found := &templatev1.ConstraintTemplate{}
	expected := res.BuildConstraintTemplateForIShield(instance)

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ConstraintTemplate.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil
}

func (r *IntegrityShieldReconciler) isGatekeeperAvailable(instance *apiv1.IntegrityShield) bool {
	ctx := context.Background()
	found := &extv1.CustomResourceDefinition{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ConstraintTemplate.Name", "constrainttemplates.templates.gatekeeper.sh")

	// If Constraint template does not exist, return false
	err := r.Get(ctx, types.NamespacedName{Name: "constrainttemplates.templates.gatekeeper.sh"}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Gatekeeper constraint template crd is not found")
		return false
	} else if err != nil {
		return false
	}
	return true
}

// delete ishield-psp
func (r *IntegrityShieldReconciler) deleteConstraintTemplate(instance *apiv1.IntegrityShield) (ctrl.Result, error) {
	ctx := context.Background()
	found := &templatev1.ConstraintTemplate{}
	expected := res.BuildConstraintTemplateForIShield(instance)

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ConstraintTemplate.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info("Deleting the IShield ConstraintTemplate")
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, "Failed to delete the IShield ConstraintTemplate")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if errors.IsNotFound(err) {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else {
		return ctrl.Result{}, err
	}
}
