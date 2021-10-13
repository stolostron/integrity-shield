# k8s Integrity Shield

Kubernetes resources are represented as YAML files, which are applied to clusters when you create and update the resource. The YAML content is designed carefully to achieve the application desired state and should not be tampered with. If the YAML content is modified maliciously or accidentally, and applied to a cluster without notice, the cluster moves to an unexpected state.

[K8s Integrity Shield](https://github.com/open-cluster-management/integrity-shield) provides preventive control for enforcing signature verification for any requests to create or update resources. This operator supports the installation and management of K8s Integrity Shield on cluster. 

Two modes are selectively enabled on your cluster. 
- Enforce (Admission Control): Block to deploy unauthorized Kubernetes resources. K8s Integrity Shield works with OPA/Gatekeeper to enable admission control based on signature verification for Kubernetes resources.
- Detect (Continuous Monitoring): monitor Kubernetes resource integrity and report if unauthorized Kubernetes resources are deployed on cluster

X509, PGP and Sigstore signing are supported for singing Kubernetes manifest YAML. K8s Integrity Shield supports Sigstore signing by using [k8s-manifest-sigstore](https://github.com/sigstore/k8s-manifest-sigstore).

## Preparations before installation

OPA/Gatekeeper should be deployed before installing K8s Integrity Shield.
The installation instructions to deploy OPA/Gatekeeper components is [here](https://open-policy-agent.github.io/gatekeeper/website/docs/install/).


## Installation
Install K8s Integrity Shield Operator by following the instruction after clicking Install button at the top right. Then you can create the operator Custom Resource `IntegrityShield` to complete installation.

If you want to change the settings such as default run mode (detection/enforcement) or audit interval,  please check [here](https://github.com/open-cluster-management/integrity-shield/blob/master/docs/README_ISHIELD_OPERATOR_CR.md).

To verify that installation was completed successfully,
run the following command.
The following three pods will be installed with default CR.
```
$ kubectl get pod -n integrity-shield-operator-system                                                                                                                  
NAME                                                            READY   STATUS    RESTARTS   AGE
integrity-shield-api-7b7f768bf7-fhrpg                           1/1     Running   0          20s
integrity-shield-observer-5bc66f75f7-tn8fw                      1/1     Running   0          25s
integrity-shield-operator-controller-manager-65b7fb58f7-j25zd   2/2     Running   0          3h5m
```

After installation, you can protect Kubernetes resources by following this [document](https://github.com/open-cluster-management/integrity-shield/blob/master/docs/README_GETTING-STARTED-TUTORIAL.md).

## Supported Versions
### Platform
K8s Integrity Shield can be deployed with the operator. We have verified the feasibility on the following platforms:

- [RedHat OpenShift 4.7.1 and 4.9.0](https://www.openshift.com)  
- [Kuberenetes v1.19.7 and v1.21.1](https://kubernetes.io)

### OPA/Gatekeeper
- [gatekeeper-operator v0.2.0](https://github.com/open-policy-agent/gatekeeper)
- [gatekeeper v3.5.2 and v3.6.0](https://github.com/open-policy-agent/gatekeeper)