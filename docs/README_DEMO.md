# README_DEMO

## Prerequisites
The following prerequisites must be satisfied to deploy IShield on a cluster.
- A Kubernetes cluster and cluster admin access to the cluster to use `kubectl` command


## Install Integrity Shield and see how Integrity Shield verifies integrity of a sample resource
This section describe how to use demo script for deploying Integrity Shield (IShield) on your cluster and see how it protect integrity of resources.

### Retrive the source from `integrity-enforcer` Git repository.

git clone this repository and moved to `integrity-enforcer` directory

```
$ git clone https://github.com/open-cluster-management/integrity-shield.git
$ cd integrity-shield
$ pwd /home/repo/integrity-enforcer
```
In this document, we clone the code in `/home/repo/integrity-enforcer`.

###  Setup environment variable.

Setup `ISHIELD_ROOT_REPO` as below. `/home/repo/integrity-enforcer` is the root directory where Integrity Shield is cloned.
```
$ export ISHIELD_REPO_ROOT=/home/repo/integrity-enforcer
```

Setup `KUBECONFIG` as below.  `~/kube/config/minikube` is the Kuebernetes config file with credentials for accessing a cluster via `kubectl`.
```
$ export KUBECONFIG=~/kube/config/minikube
```

### Execute demo script in `/home/repo/integrity-enforcer/demo/quick-start/`
```
$ cd demo/quick-start/
$ ./demo.sh
```
