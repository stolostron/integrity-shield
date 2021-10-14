# Quick Start

## Prerequisites
​
The following prerequisites must be satisfied to deploy Integrity Shield on a cluster.
- A Kubernetes cluster and cluster admin access to the cluster to use `oc` or `kubectl` command

---

## Install Integrity Shield
​
This section describe the steps for deploying Integrity Shield (IShield) on your cluster. We will use RedHat OpenShift cluster and so use `oc` commands for installation. (You can use `kubectl` for Minikube or IBM Kubernetes Service.)

### Retrive the source from `integrity-enforcer` Git repository.

git clone this repository and moved to `integrity-enforcer` directory

```
$ git clone https://github.com/open-cluster-management/integrity-shield.git
$ cd integrity-shield
$ pwd /home/repo/integrity-enforcer
```
In this document, we clone the code in `/home/repo/integrity-enforcer`.

### Prepare namespace for installing Integrity Shield

You can deploy Integrity Shield to any namespace. In this document, we will use `integrity-shield-operator-system` to deploy Integrity Shield.
```
make create-ns

```
We switch to `integrity-shield-operator-system` namespace.
```
oc project integrity-shield-operator-system
```
All the commands are executed on the `integrity-shield-operator-system` namespace unless mentioned explicitly.

### Define public key secret in Integrity Shield

Integrity Shield requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.  Integrity Shield supports X509 or PGP key for signing resources. The following steps show how you can import your signature verification key to Integrity Shield.

First, you need to export public key to a file. The following example shows a pubkey for a signer identified by an email `sample_signer@enterprise.com` is exported and stored in `/tmp/pubring.gpg`. (Use the filename `pubring.gpg`.)

```
$ gpg --export sample_signer@enterprise.com > /tmp/pubring.gpg
```

If you do not have any PGP key or you want to use new key, generate new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key).

Then, create a secret that includes a pubkey ring for verifying signatures of resources

```
oc create secret generic --save-config keyring-secret  -n integrity-shield-operator-system --from-file=/tmp/pubring.gpg
```

### Define signers for each namespace


You can define signer who can provide signature for resources on each namespace. It can be configured when deploying the Integrity Shield. For that, configure signerConfig in the following Integrity Shield Custom Resource [file](../integrity-shield-operator/config/samples/apis_v1alpha1_integrityshield.yaml). Example below shows a signer `SampleSigner` identified by email `sample_signer@enterprise.com` is configured to sign rosources to be protected in any namespace and the corresponding verification key (i.e. keyring-secret) under `keyConfig`

```yaml
# Edit integrity-shield-operator/config/samples/apis_v1alpha1_integrityshield.yaml
apiVersion: apis.integrityshield.io/v1alpha1
kind: IntegrityShield
metadata:
  name: integrity-shield-server
spec:
  namespace: integrity-shield-operator-system
  shieldConfig:
    verifyType: pgp # x509
    inScopeNamespaceSelector:
      include:
      - "*"
      exclude:
      - "kube-*"
      - "openshift-*"
  signerConfig:
    policies:
    - namespaces:
      - "*"
      signers:
      - "SampleSigner"
    - scope: "Cluster"
      signers:
      - "SampleSigner"
    signers:
    - name: "SampleSigner"
      keyConfig: sample-signer-keyconfig
      subjects:
      - email: "signer@enterprise.com"
  keyConfig:
  - name: sample-signer-keyconfig
    secretName: keyring-secret


```



### Install Integrity Shield to a cluster

Integrity Shield can be installed to a cluster using a series of steps which are bundled in a script called [`install_shield.sh`](../scripts/install_shield.sh). Before executing the script `install_shield.sh`, setup local environment as follows:
- `ISHIELD_ENV <local: means that we deploy IShield to a local cluster like Minikube>`
- `ISHIELD_REPO_ROOT=<set absolute path of the root directory of cloned integrity-shield source repository`
- `KUBECONFIG=~/kube/config/minikube`  (for deploying IShield on minikube cluster)

`~/kube/config/minikube` is the Kuebernetes config file with credentials for accessing a cluster via `kubectl`.

Example:
```
$ export ISHIELD_ENV=local
$ export ISHIELD_REPO_ROOT=/home/repo/integrity-enforcer
$ export KUBECONFIG=~/kube/config/minikube
```

Prepare a private registry for hosting IShield container images, if not already exist.
The following example create a private local container image registry to host the IShield container images.

```
$ cd integrity-shield
$ make create-private-registry
```

Execute the following make commands to build Integrity Shield images.
```
$ cd integrity-shield
$ make build-images
$ make push-images-to-local
```

Then, execute the following script to deploy Integrity Shield in a cluster.

```
$ make install-crds
$ make install-operator
$ make make setup-tmp-cr
$ make create-tmp-cr
```

After successful installation, you should see two pods are running in the namespace `integrity-shield-operator-system`.

```
$ oc get pod -n integrity-shield-operator-system
integrity-shield-operator-c4699c95c-4p8wp   1/1     Running   0          5m
integrity-shield-server-85c787bf8c-h5bnj    2/2     Running   0          82m
```

---

## Protect Resources with Integrity Shield
​
Once Integrity Shield is deployed to a cluster, you are ready to put resources on the cluster into signature-based protection. To start actual protection, you need to define which resources should be protected specifically. This section describes the execution flow for protecting a specific resource (e.g. ConfigMap) in a specific namespace (e.g. `secure-ns`) on your cluster.

The steps for protecting resources include:
- Define which reource(s) should be protected.
- Create a resource with signature.

### Define which reource(s) should be protected

You can define which resources should be protected with signature in a cluster by Integrity Shield. A custom resource `ResourceSigningProfile` (RSP) includes the definition and it is created in the same namespace as resources. Example below illustrates how to define RSP to protect three resources ConfigMap, Deployment, and Service in a namespace `secure-ns`. After this, any resources specified here cannot be created/updated without valid signature.

```
$ cat <<EOF | oc apply -n secure-ns -f -
apiVersion: apis.integrityshield.io/v1alpha1
kind: ResourceSigningProfile
metadata:
  name: sample-rsp
spec:
  protectRules:
  - match:
    - kind: ConfigMap
    - kind: Deployment
    - kind: Service
EOF

resourcesigningprofile.apis.integrityshield.io/sample-rsp created
```

See [Define Protected Resources](README_FOR_RESOURCE_SIGNING_PROFILE.md) for detail specs.

### Create a resource with signature

Any configmap cannot be created without signature in `secure-ns` namespace. Run the following command to create a sample configmap.

```
cat << EOF > /tmp/test-cm.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
data:
  key1: val1
  key2: val2
  key4: val4
EOF
```


run the command below for trying to create the configmap in `secure-ns` namespace without signature. You will see it is blocked because no signature for this resource is stored in the cluster.

```
$ oc apply -f /tmp/test-cm.yaml -n secure-ns
Error from server: error when creating "test-cm.yaml": admission webhook "ac-server.integrity-shield-operator-system.svc" denied the request: Signature verification is required for this request, but no signature is found. Please attach a valid signature to the annotation or by a ResourceSignature, Request: {"kind":"ConfigMap","name":"test-cm","namespace":"secure-ns","operation":"CREATE","request.uid":"cfea7d34-0bf0-4e6a-9b59-e53290e02e67","scope":"Namespaced","userName":"kubernetes-admin"}
```


To generate a signature for a resource, you can use a [utility script](../scripts/gpg-rs-sign.sh) (Use [yq](https://github.com/mikefarah/yq) in the script)

Run the following script to generate a signature

```
$ ./scripts/gpg-rs-sign.sh signer@enterprise.com /tmp/test-cm.yaml /tmp/test-cm-rs.yaml
```


Then, output file `/tmp/test-cm-rs.yaml` is A custom resource `ResourceSignature` which includes signature of the input yaml.


```yaml
apiVersion: apis.integrityshield.io/v1alpha1
kind: ResourceSignature
metadata:
  annotations:
    integrityshield.io/messageScope: spec
    integrityshield.io/signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t
  name: rsig-test-cm
spec:
  data:
    - message: YXBpVmVyc2lvbjogdjEKa2luZDogQ29u
      signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t
      type: resource
```


Create this resource.
```
$ oc create -f /tmp/test-cm-rs.yaml -n secure-ns
resourcesignature.apis.integrityshield.io/rsig-test-cm created
```


Then, run the same command again to create ConfigMap. It should be successful this time because a corresponding ResourceSignature is available in the cluster.

```
$ oc create -f /tmp/test-cm.yaml -n secure-ns
configmap/test-cm created
```


You can see all denied requests as Kubernetes Event like below.

```
$ oc get event -n secure-ns --field-selector type=IntegrityShield

LAST SEEN   TYPE              REASON         OBJECT                MESSAGE
27s         IntegrityShield   no-signature   configmap/test-cm   [IntegrityShieldEvent] Result: deny, Reason: "Signature verification is required for this request, but no signature is found. Please attach a valid signature to the annotation or by a ResourceSignature.", Request: {"kind":"ConfigMap","name":"test-cm","namespace":"secure-ns","operation":"CREATE","request.uid":"cfea7d34-0bf0-4e6a-9b59-e53290e02e67","scope":"Namespaced","userName":"kubernetes-admin"}
```

### Clean up Integrity Shield from the cluster

When you want to remove Integrity Shield from a cluster, run the uninstaller script [`delete_shield.sh`](../scripts/delete_shield.sh).
```
$ cd integrity-shield
$ make delete-tmp-cr
$ make delete-operator
```


