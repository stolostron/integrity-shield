# k8s Integrity Shield

[Integrity Shield](https://github.com/open-cluster-management/integrity-shield) provides signature-based assurance of integrity for Kubernetes resources at cluster side.  

Current features:
- Work with [OPA/Gatekeeper](https://github.com/open-policy-agent/gatekeeper) to enable signature verification for Kubernetes resources.
- Block to deploy unauthorized Kubernetes resources in enforcement mode.
- Monitor Kubernetes resource integrity and report if unauthorized Kubernetes resources are deployed on cluster. 
- Support x509, PGP and [Sigstore](https://www.sigstore.dev) signing
- Use [k8s-manifest-sigstore](https://github.com/sigstore/k8s-manifest-sigstore) internally to verify Kubernetes resources

This operator supports the installation and upgrade of Integrity Shield.

## Preparations before installation

Default CR includes the configuration which enable linkage with gatekeeper, so OPA/Gatekeeper should be deployed before installing Integrity Shield.
The installation instructions to deploy Gatekeeper components is [here](https://open-policy-agent.github.io/gatekeeper/website/docs/install/).


## Installation
Install Integrity Shield Operator by following the instruction after clicking Install button at the top right. Then you can create the operator Custom Resource `IntegrityShield` to complete installation.

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

## Supported Versions
### Platforms
Integrity Shield can be deployed with operator. We have verified the feasibility on the following platforms:

- [RedHat OpenShift 4.7.1 and 4.9.0](https://www.openshift.com)  
- [Kuberenetes v1.19.7 and v1.21.1](https://kubernetes.io)

### OPA/Gatekeeper
- [gatekeeper-operator.v0.2.0](https://github.com/open-policy-agent/gatekeeper)
- [gatekeeper v3.5](https://github.com/open-policy-agent/gatekeeper)