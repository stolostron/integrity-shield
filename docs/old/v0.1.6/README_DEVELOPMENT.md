# Development

## Clone Repo
```
$ git clone git@github.com:open-cluster-management/integrity-shield.git
$ cd integrity-shield
```

## Setup
Before executing the script, setup local environment as follows:

- `ISHIELD_REPO_ROOT`: set absolute path of the root directory of cloned integrity-shield source repository
- `KUBECONFIG=~/kube/config/minikube`  (for deploying IShield on minikube cluster)

`~/kube/config/minikube` is the Kuebernetes config file with credentials for accessing a cluster via `kubectl`.

For example
```
$ export KUBECONFIG=~/kube/config/minikube
$ export ISHIELD_REPO_ROOT=/repo/integrity-enforcer
$ export ISHIELD_ENV=local
```

## Make commands

### Create private registry for hosting IShield container images

The following example create a private local container image registry to host the IShield container images.
```
$ make create-private-registry
```

### Build IShield container images
```
$ make build-images
$ make tag-images-to-local
```

The make commands refer the steps for
- Building Integrity Shield container images
- Tagging Integrity Shield container images to be used locally.

Three images are built.
- `integrity-shield-operator` is image for operator which manages Integrity Shield
- `integrity-shield-server` is image for IShield server
- `integrity-shield-logging` is image for IShield logging side car

### Push images

The following command pushes the built IShield images to local container image registry setup above.
```
$ make push-images-to-local
```

Alternatively, you can push images to other container image registry as below.

```
$ make push-images
```

You may need to setup image registry (e.g. dockerhub, quay.io etc.) and change the container images' name and tag as needed.

For example
```
$ export DOCKER_REGISTRY=docker.io
$ export DOCKER_USER=integrityshield
$ export DOCKER_PASS=<password>
```

### Install IShield to a cluster

Create verification key as a secret.

The following creates default key-ring secret required by IShield server.
```
make create-key-ring
```

```
$ make install-crds
$ make install-operator
$ make setup-tmp-cr
$ make create-tmp-cr
```

The make commands refer the steps for
- Create CRDs
- Install Integrity Shield operator
- Prepare Integrity Shield custom resource (operator installs IShield server automatically)
- Install Integrity Shield custom resource (operator installs IShield server automatically)

### Uninstall IShield from cluster
```
$ make delete-tmp-cr
$ make delete-keyring-secret
$ make delete-operator
```

The make command refers to the steps for
- Delete Integrity Shield custom resource (operator installs IShield server automatically)
- Delete Key-ring secret
- Delete Integrity Shield operator
- Delete CRDs

