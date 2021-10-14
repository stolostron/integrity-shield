# Quick Start

## Prerequisites
​
The following prerequisites must be satisfied to deploy Integrity Shield on a cluster.
- A Kubernetes cluster and cluster admin access to the cluster to use `oc` or `kubectl` command
- Gatekeeper should be running on a cluster. The installation instructions to deploy OPA/Gatekeeper components is [here](https://open-policy-agent.github.io/gatekeeper/website/docs/install/).
In this document, we use gatekeeper v3.6.0.
```
$ kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.6/deploy/gatekeeper.yaml
```
---

## Install Integrity Shield
​
This section describe the steps for deploying Integrity Shield (IShield) on your cluster. Here, We will use [kind](https://kind.sigs.k8s.io) which is a tool for running local Kubernetes clusters using Docker container “nodes”.

### Retrive the source from `integrity-shield` Git repository.

git clone this repository and moved to `integrity-shield` directory

```
$ git clone https://github.com/open-cluster-management/integrity-shield.git
$ cd integrity-shield
$ pwd /home/repo/integrity-shield
```
In this document, we clone the code in `/home/repo/integrity-shield`.

### Setup environment
setup local environment as follows:
- `ISHIELD_TEST_ENV <local: means that we deploy IShield to a local cluster like Kind cluster>`
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

Prepare a Kubernets cluster and private registry, if not already exist.
The following example create a kind cluster which is a local Kubernetes cluster and a private local container image registry to host the IShield container images.

```
$ make create-kind-cluster
```


### Prepare namespace for installing Integrity Shield

You can deploy Integrity Shield to any namespace. In this document, we will use `integrity-shield-operator-system` to deploy Integrity Shield.

If you want to use another namespace, please change `ISHIELD_NS` variable in this [file](../ishield-build.conf).
```
make create-ns
```

### Install Integrity Shield to a cluster

Integrity Shield can be installed to a cluster with simple steps.

Execute the following make commands to build Integrity Shield images.
In this document, we push images to local image registry `localhost:5000` because we set ISHIELD_TEST_ENV=local.
If you want to use another registry, please change `LOCAL_REGISTRY` variable in this [file](../ishield-build.conf).

```
$ make build-images
$ make push-images-to-local
```

Then, execute the following command to deploy Integrity Shield Opertor in a cluster.

```
$ make install-operator
$ make make setup-tmp-cr
$ make create-tmp-cr
```

After successful installation, you should see a pod is running in the namespace `integrity-shield-operator-system`.

```
$ kubectl get pod -n integrity-shield-operator-system                                                                     
NAME                                                            READY   STATUS    RESTARTS   AGE
integrity-shield-operator-controller-manager-6df99c6c58-79tdn   2/2     Running   0          39s
```
Then, execute the following command to deploy Integrity Shield API and Observer in a cluster.

```
$ make create-tmp-cr
```
After successful installation, you should see a pod is running in the namespace `integrity-shield-operator-system`.
```
$ kubectl get pod -n integrity-shield-operator-system                                                                    
NAME                                                            READY   STATUS    RESTARTS   AGE
integrity-shield-api-7b7f768bf7-ppj86                           1/1     Running   0          20s
integrity-shield-observer-66ffcfc544-j7wqf                      1/1     Running   0          23s
integrity-shield-operator-controller-manager-6df99c6c58-79tdn   2/2     Running   0          2m39s
```

---
## Protect Resources with Integrity Shield
​
Once Integrity Shield is deployed to a cluster, you are ready to put resources on the cluster into signature-based protection. To start actual protection, you need to define which resources should be protected specifically. This section describes the execution flow for protecting a specific resource (e.g. ConfigMap) in a specific namespace (e.g. `secure-ns`) on your cluster.

The steps for protecting resources include:
- Store verification key as a Kubernetes Secret
- Configure ManifestIntegrityProfile to define which reource(s) should be protected

and try two modes:
- [Detect] Check resource integrity on cluster 
- [Enforce] Enable preventive protection 

Integrity Shield provides a phased approach. It allows users to use signature-based protection first in detection mode and then switch to enforcement mode.

### Store verification key as a Kubernetes Secret

Integrity Shield requires a secret that includes a pubkey for verifying signatures of resources that need to be protected.  Integrity Shield supports X509, PGP or Sigstore key for signing resources.
In this document, we use pgp signing.

The following steps show how you can import your signature verification key to Integrity Shield.  
Find out how to sign your resources [here](README_SIGNING.md).

First, you need to export public key to a file. The following example shows a pubkey for a signer identified by an email `sample_signer@enterprise.com` is exported and stored in `/tmp/pubring.gpg`. (Use the filename `pubring.gpg`.)

```
$ gpg --export sample_signer@enterprise.com > /tmp/pubring.gpg
```

If you do not have any PGP key or you want to use new key, generate new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key).

Then, create a secret that includes a pubkey ring for verifying signatures of resources

```
kubectl create secret generic --save-config keyring-secret  -n integrity-shield-operator-system --from-file=/tmp/pubring.gpg
```

### Define which reource(s) should be protected

You can define which resources should be protected with signature in a cluster by Integrity Shield. A custom resource `ManifestIntegrityConstraint` (MIC) includes the definition. Example below illustrates how to define ManifestIntegrityConstraint to protect three resources ConfigMap, Deployment, and Service in a namespace `secure-ns`. 

Integrity Shield provides phased approach.
First, let's try **`Detect mode`**.

```
cat <<EOF | kubectl apply -f -
  apiVersion: constraints.gatekeeper.sh/v1beta1
  kind: ManifestIntegrityConstraint
  metadata:
    name: sample-constraint
  spec:
    match:
      kinds:
      - apiGroups:
        - ""
        kinds:
        - ConfigMap
        - Service
      - apiGroups:
        - "apps"
        kinds:
        - Deployment
      namespaces:
      - "secure-ns"
    parameters:
      action:
        admissionControl:
          enforce: false
        audit:
          inform: true
      constraintName: sample-constraint
      signers:
      - sample_signer@enterprise.com
      keyConfigs:
      - keySecretName: my-pubkey
        keySecretNamespace: integrity-shield-operator-system
EOF

manifestintegrityconstraint.constraints.gatekeeper.sh/sample-constraint created
```

See [Define Protected Resources](README_CONSTRAINT.md) for detail specs.

### Create a sample resource without signature
Run the following command to create a sample configmap.
```
cat << EOF > /tmp/sample-cm.yaml
  apiVersion: v1
  kind: ConfigMap
  metadata:
    name: sample-cm
  data:
    key1: val1
    key2: val2
    comment: comment1
EOF
```

Create a sample configmap by the command below, and the configmap will be created because of detection mode.
```
$ kubectl apply -f /tmp/sample-cm.yaml -n secure-ns
configmap/sample-cm created
```


### Check the resource integrity status from the ManifestIntegrityState generated by observer
Check the results of resource integrity verification by observer with this command.
you can see that some resources defined in sample-constraint are in invalid state because integrityshield.io/verifyResourceViolation label is true.
```
$ kubectl get mis --show-labels -n integrity-shield-operator-system                                                                                             
NAME                   AGE    LABELS
sample-constraint      2m1s   integrityshield.io/verifyResourceIgnored=false,integrityshield.io/verifyResourceViolation=true
```
By checking verification result on per constraint, you can see which resources are violated from ManifestIntegrityState.
```
$ kubectl get mis sample-constraint -n integrity-shield-operator-system -o yaml                                                                               
apiVersion: apis.integrityshield.io/v1
kind: ManifestIntegrityState
metadata:
  labels:
    integrityshield.io/verifyResourceIgnored: "false"
    integrityshield.io/verifyResourceViolation: "true"
  name: sample-constraint
  namespace: integrity-shield-operator-system
spec:
  constraintName: sample-constraint
  nonViolations: null
  observationTime: "2021-10-14 13:04:55"
  totalViolations: 1
  violation: true
  violations:
  - apiGroup: ""
    apiVersion: v1
    kind: ConfigMap
    name: sample-cm
    namespace: secure-ns
    result: 'failed to verify signature: failed to get signature: `cosign.sigstore.dev/message`
      is not found in the annotations'
status: {}
```
### Create a resource with signature

Generate siganture with the following command. Please see this [document](README_SIGNING.md).

```
$ ./scripts/gpg-annotation-sign.sh sample_signer@enterprise.com /tmp/sample-cm.yaml
```
Check the signature is attached to the sample resource.
```
$ less /tmp/sample-cm.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sample-cm
  annotations:
    integrityshield.io/message: H4sIAMmiZmEAAzXLMQqAMAyF4T...
    integrityshield.io/signature: LS0tLS1CRUdJTiBQR1AgU...
data:
  key1: val1
  key2: val2
  comment: comment1
```
Apply a sample configmap by the command below.
```
$ kubectl apply -f /tmp/sample-cm.yaml -n secure-ns
configmap/sample-cm created
```

Check the resource integrity status again. You can see that `integrityshield.io/verifyResourceViolation` label became false.

```
$ kubectl get mis --show-labels -n integrity-shield-operator-system
NAME                   AGE   LABELS
sample-constraint      22m   integrityshield.io/verifyResourceIgnored=false,integrityshield.io/verifyResourceViolation=false
```
Also, you can see sample-cm has no violation because it has valid signature now.
```
$ kubectl get mis sample-constraint -n integrity-shield-operator-system -o yaml            
apiVersion: apis.integrityshield.io/v1
kind: ManifestIntegrityState
metadata:
  labels:
    integrityshield.io/verifyResourceIgnored: "false"
    integrityshield.io/verifyResourceViolation: "false"
  name: sample-constraint
  namespace: integrity-shield-operator-system
spec:
  constraintName: sample-constraint
  nonViolations:
  - apiGroup: ""
    apiVersion: ""
    kind: ConfigMap
    name: sample-cm
    namespace: secure-ns
    result: 'singed by a valid signer: sample_signer@enterprise.com'
    sigRef: __embedded_in_annotation__
    signer: sample_signer@enterprise.com
  observationTime: "2021-10-14 13:24:54"
  totalViolations: 0
  violation: false
  violations: null
status: {}
```

### Reconfigure ManifestIntegrityConstraint to turn on Enforce mode

Now, let's switch to  **`Enforce mode`**.

To enable enforce mode, change `enforce: false` to `enforce: true`, then create ManifestIntegrityConstraint.
```
cat <<EOF | kubectl apply -f -
  apiVersion: constraints.gatekeeper.sh/v1beta1
  kind: ManifestIntegrityConstraint
  metadata:
    name: sample-constraint
  spec:
    match:
      kinds:
      - apiGroups:
        - ""
        kinds:
        - ConfigMap
        - Service
      - apiGroups:
        - "apps"
        kinds:
        - Deployment
      namespaces:
      - "secure-ns"
    parameters:
      action:
        admissionControl:
          enforce: true
        audit:
          inform: true
      constraintName: sample-constraint
      signers:
      - sample_signer@enterprise.com
      keyConfigs:
      - keySecretName: my-pubkey
        keySecretNamespace: integrity-shield-operator-system
EOF

```

### Create a sample resource without signature

Run the following command to create a sample service.
```
cat << EOF > /tmp/sample-svc.yaml
apiVersion: v1
kind: Service
metadata:
  name: sample-service
spec:
  selector:
    app: SampleApp
  ports:
    - protocol: TCP
      port: 80
      targetPort: 9376
EOF
```
Create a sample service by the command below, and the service will be blocked because the signature verification fails.

```
$ kubectl create -f /tmp/sample-svc.yaml -n secure-ns                                                                 
Error from server ([sample-constraint] denied; {"allow": false, "message": "failed to verify signature: failed to get signature: `cosign.sigstore.dev/message` is not found in the annotations"}): error when creating "/tmp/sample-svc.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [sample-constraint] denied; {"allow": false, "message": "failed to verify signature: failed to get signature: `cosign.sigstore.dev/message` is not found in the annotations"}
```

You can see denied requests as Kubernetes Event like below.
```
$ kubectl get event -n secure-ns --field-selector type=IntegrityShield                                                     
LAST SEEN   TYPE              REASON   OBJECT                   MESSAGE
65s         IntegrityShield   Deny     service/sample-service   [sample-constraint]failed to verify signature: failed to get signature: `cosign.sigstore.dev/message` is not found in the annotations
```

### Generate the signature for the sample resource
Generate a signature for a resource. Run the following script to generate a signature.

```
$ ./scripts/gpg-annotation-sign.sh sample_signer@enterprise.com /tmp/sample-svc.yaml
```

Then, run the same command again to create Service. It should be successful this time because the resource has valid siganture.

```
$ kubectl create -f /tmp/sample-svc.yaml -n secure-ns                                                                
service/sample-service created
```

You can confirm that all protected resources are valid.
```
kind: ManifestIntegrityState
metadata:
  creationTimestamp: "2021-10-14T13:04:55Z"
  generation: 18
  labels:
    integrityshield.io/verifyResourceIgnored: "false"
    integrityshield.io/verifyResourceViolation: "false"
  name: sample-constraint
  namespace: integrity-shield-operator-system
spec:
  constraintName: sample-constraint
  nonViolations:
  - apiGroup: ""
    apiVersion: ""
    kind: Service
    name: sample-service
    namespace: secure-ns
    result: 'singed by a valid signer: sample_signer@enterprise.com'
    sigRef: __embedded_in_annotation__
    signer: sample_signer@enterprise.com
  - apiGroup: ""
    apiVersion: v1
    kind: ConfigMap
    name: sample-cm
    namespace: secure-ns
    result: 'singed by a valid signer: sample_signer@enterprise.com'
    sigRef: __embedded_in_annotation__
    signer: sample_signer@enterprise.com
  observationTime: "2021-10-14 14:29:49"
  totalViolations: 0
  violation: false
  violations: null
status: {}
```

### Clean up Integrity Shield from the cluster

When you want to remove Integrity Shield from a cluster, run the following commands.
```
$ cd integrity-shield
$ make delete-tmp-cr
$ make delete-operator
```


