# Developer Guide 

## Quick Start for Development

This document will guide you through:
- how to install Integrity Shield with make commands
- how to use your own image registry for Integrity Shield
- how to install Integrity Shield in another namespace
- how to see log

### Prerequisites
​
The following prerequisites must be satisfied to deploy Integrity Shield on a cluster.
- A Kubernetes cluster and cluster admin access to the cluster to use `oc` or `kubectl` command
- Gatekeeper should be running on a cluster. The installation instructions to deploy OPA/Gatekeeper components is [here](https://open-policy-agent.github.io/gatekeeper/website/docs/install/).
In this document, we use gatekeeper v3.6.0.
```
$ kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.6/deploy/gatekeeper.yaml
```
---

### Install Integrity Shield
​
This section describes the steps for deploying Integrity Shield on your cluster. Here, We will use [kind](https://kind.sigs.k8s.io), which is a tool for running local Kubernetes clusters using Docker container “nodes”.

### Retrive the source from `integrity-shield` Git repository.

Git clone this repository and moved to `integrity-shield` directory

```
$ git clone https://github.com/stolostron/integrity-shield.git
$ cd integrity-shield
$ pwd /home/repo/integrity-shield
```
In this document, we clone the code in `/home/repo/integrity-shield`.

### Setup environment
Setup local environment as follows:
- `ISHIELD_TEST_ENV <local: means that we deploy Integrity Shield to a local cluster like Kind cluster>`
- `ISHIELD_REPO_ROOT=<set absolute path of the root directory of cloned integrity-shield source repository`
- `KUBECONFIG=~/kube/config/kind`  (for deploying Integrity Shield on kind cluster)

`~/kube/config/kind` is the Kuebernetes config file with credentials for accessing a cluster via `kubectl`.

Example:
```
$ export ISHIELD_TEST_ENV=local
$ export ISHIELD_REPO_ROOT=/home/repo/integrity-shield
$ export KUBECONFIG=~/kube/config/kind
```

### Prepare Kubernets cluster and private registry

Prepare a Kubernetes cluster and private registry, if not already exist.
The following example creates a kind cluster which is a local Kubernetes cluster and a private local container image registry to host the Integrity Shield container images.

```
$ make create-kind-cluster
```


### Prepare namespace for installing Integrity Shield

You can deploy Integrity Shield to any namespace. In this document, we will use `integrity-shield-operator-system` to deploy Integrity Shield.

If you want to use another namespace, please change the `ISHIELD_NS` variable in this [file](../ishield-build.conf).
```
make create-ns
```

### Install Integrity Shield to a cluster

Execute the following command to build Integrity Shield images.
In this document, we push images to the local image registry `localhost:5000` because we set ISHIELD_TEST_ENV=local.
If you want to use another registry, please change the `LOCAL_REGISTRY` variable in this [file](../ishield-build.conf).

```
$ make build-images
$ make push-images-to-local
```

Then, execute the following command to deploy Integrity Shield Operator in a cluster

```
$ make install-operator
$ make make setup-tmp-cr
$ make create-tmp-cr
```

After successful installation, you should see a pod running in the namespace `integrity-shield-operator-system`.

```
$ kubectl get pod -n integrity-shield-operator-system                                                                     
NAME                                                            READY   STATUS    RESTARTS   AGE
integrity-shield-operator-controller-manager-6df99c6c58-79tdn   2/2     Running   0          39s
```
Then, execute the following command to deploy Integrity Shield API and Observer in a cluster.

```
$ make create-tmp-cr
```

After successful installation, you should see a pod running in the namespace `integrity-shield-operator-system`.

```
$ kubectl get pod -n integrity-shield-operator-system                                                                    
NAME                                                            READY   STATUS    RESTARTS   AGE
integrity-shield-api-7b7f768bf7-ppj86                           2/2     Running   0          20s
integrity-shield-observer-66ffcfc544-j7wqf                      1/1     Running   0          23s
integrity-shield-operator-controller-manager-6df99c6c58-79tdn   2/2     Running   0          2m39s
```

### Protect Resources with Integrity Shield
See this [document](README_GETTING-STARTED-TUTORIAL.md) 

### Check Integrity Shield log
Execute the following commands to check Integrity Shield Operator, API and Observer log.

```
$ make log-operator
$ make log-api
$ make log-observer
```

### Clean up Integrity Shield from the cluster

When you want to remove Integrity Shield from a cluster, run the following commands.
```
$ cd integrity-shield
$ make delete-tmp-cr
$ make delete-operator
```


