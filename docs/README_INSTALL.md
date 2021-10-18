# Installation
There are two ways to install Integrity Shield.
- OLM
- Operator Manual Install

### Prerequisite
Before installing Integrity Shield, [OPA/Gatekeeper](https://github.com/open-policy-agent/gatekeeper) should be installed on the cluster.

## OLM
1. Install Integrity Shield Operator using OLM

Please click the `Install` button in the upper right corner of this [document](https://operatorhub.io/operator/integrity-shield-operator) and follow the instructions.

2. Install Integrity Shield CR

```
kubectl create -f https://raw.githubusercontent.com/open-cluster-management/integrity-shield/master/integrity-shield-operator/config/samples/apis_v1_integrityshield.yaml -n integrity-shield-operator-system
```

## Operator Manual Install
You can install Integrity Shield the following two steps.
1. Install Integrity Shield Operator

This Operator will be installed in the "integrity-shield-operator-system" namespace.
```
kubectl create -f https://raw.githubusercontent.com/open-cluster-management/integrity-shield/master/integrity-shield-operator/deploy/integrity-shield-operator-latest.yaml
```

2. Install Integrity Shield CR

```
kubectl create -f https://raw.githubusercontent.com/open-cluster-management/integrity-shield/master/integrity-shield-operator/config/samples/apis_v1_integrityshield.yaml -n integrity-shield-operator-system
```


## Verify installation
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