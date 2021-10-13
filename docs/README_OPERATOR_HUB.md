# k8s Integrity Shield

[Integrity Shield](https://github.com/open-cluster-management/integrity-shield) provides signature-based assurance of integrity for Kubernetes resources at cluster side.  

Current features:
- Work with [OPA/Gatekeeper](https://github.com/open-policy-agent/gatekeeper) to enforce admission requests.
- Block to deploy unauthorized Kubernetes manifests in enforcement mode.
- Monitor Kubernetes resource integrity and alert if unauthorized Kubernetes manifests are deployed on the cluster. 
- Support x509, PGP and [Sigstore](https://www.sigstore.dev) signing
- Use [k8s-manifest-sigstore](https://github.com/sigstore/k8s-manifest-sigstore) internally to verify Kubernetes manifest

This operator supports the installation and upgrade of Integrity Shield.

## Preparations before installation

Default CR includes the configuration which enable linkage with gatekeeper,  
so OPA/Gatekeeper should be deployed before installing Integrity Shield.
The installation instructions to deploy Gatekeeper components is [here](https://open-policy-agent.github.io/gatekeeper/website/docs/install/).

If you want to change the settings such as default run mode (detection/enforcement) or audit interval,  please check [here](https://github.com/open-cluster-management/integrity-shield/blob/master/docs/README_ISHIELD_OPERATOR_CR.md).

## Installation
Install Integrity Shield operator by following instructions in top right button Install. After installing the operator, create an instance of the IntegrityShield resource to install the Integrity Shield.

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

## Supported Platforms

K8s Integrity Shield can run on any Kubernetes cluster by design.
We have verified the feasibility on the following platforms:

- [RedHat OpenShift 4.7.1 and 4.9.0](https://www.openshift.com)  
- [Kuberenetes v1.19.7 and v1.21.1](https://kubernetes.io)
