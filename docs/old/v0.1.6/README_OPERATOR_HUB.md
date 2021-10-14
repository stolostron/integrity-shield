# k8s Integrity Shield

K8s Integrity Shield is a tool for built-in preventive integrity control for regulated cloud workloads. It includes signature based configuration drift prevention based on Admission Webhook on Kubernetes cluster.

K8s Integrity Shield's capabilities are

- Allow to deploy authorized application pakcages only
- Allow to use signed deployment params only
- Zero-drift in resource configuration unless whitelisted
- Perform all integrity verification on cluster (admission controller, not in client side)
- Handle variations in application packaging and deployment (Helm /Operator /YAML / OLM Channel) with no modification in app installer

## Preparations before installation

Two preparations on cluster below must be completed before installation.

1. Create a namespace `integrity-shield-operator-system`.

2. Create secret to register signature verification key.


See the following example to register public verification key from your signing host. As default, export public verification key to file "pubring.gpg" and create secret "keyring-secret" on cluster by the following command. (You can define any other name in CR if you want. See [doc](README_SIGNER_CONFIG.md))

```
# export key to file
$ gpg --export signer@enterprise.com > /tmp/pubring.gpg

# create a secret on cluster
$ oc create secret generic --save-config keyring-secret -n integrity-shield-operator-system --from-file=/tmp/pubring.gpg
```

Default CR already includes signer configuration with filename "pubring.gpg" and secret name "keyring-secret", so all you need is to create a secret resource.


## How to protect resources with signature

After installation, you can configure cluster to protect resources from creation and changes without signature.

For enabling protection, create a custom resource `ResourceSigningProfile` (RSP) that defines which resource(s) should be protected, in the same namespace as resources.

Here is an example of creating RSP for protecting resources in a namespace `secure-ns`.

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

After creating the RSP above, any resources of kinds configmap, deployment, and service can not be created or modified without valid signature.

For example, let's see what happens when creating configmap below without signature.

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

Creation of configmap is blocked, since no signature is attached to it.

```
$ oc apply -f /tmp/test-cm.yaml -n secure-ns
Error from server: error when creating "/tmp/test-cm.yaml": admission webhook "ac-server.integrity-shield-operator-system.svc" denied the request: Signature verification is required for this request, but no signature is found. Please attach a valid signature to the annotation or by a ResourceSignature. (Request: {"kind":"ConfigMap","name":"test-cm","namespace":"secure-ns","operation":"CREATE","request.uid":"61f4aabd-df4b-4d12-90e7-11a46ee28cb0","scope":"Namespaced","userName":"IAM#cluser-user"})
```

Event is reported.

```
$ oc get event -n secure-ns --field-selector type=IntegrityShield
LAST SEEN   TYPE              REASON         OBJECT              MESSAGE
65s         IntegrityShield   no-signature   configmap/test-cm   [IntegrityShieldEvent] Result: deny, Reason: "Signature verification is required for this request, but no signature is found. Please attach a valid signature to the annotation or by a ResourceSignature.", Request: {"kind":"ConfigMap","name":"test-cm","namespace":"secure-ns","operation":"CREATE","request.uid":"46cf5fde-2b46-4819-b876-a2998043c8ef","scope":"Namespaced","userName":"IAM#cluser-user"}

```

### How to sign a resource

You can sign resources with the utility script, which is available from our repository. Two prerequisites for using the script on your host.

- [yq](https://github.com/mikefarah/yq) command is available.
- you can sign file with GPG signing key of the signer registered in preparations.

For example of singing a YAML file `/tmp/test-cm.yaml` as `signer@enterprise.com`, use the utility script as shown below. This script would modify the original input file (`/tmp/test-cm.yaml`) by adding signature, message annotations to it.

```
$ curl -s https://raw.githubusercontent.com/open-cluster-management/integrity-shield/master/scripts/gpg-annotation-sign.sh | bash -s \
  signer@enterprise.com \
  /tmp/test-cm.yaml
```

Below is the sample YAML file (`/tmp/test-cm.yaml`) with signature, message annotations.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
  annotations:
    integrityshield.io/message: YXBpVmVyc2lvbjogdjEKa2luZDogQ29uZmlnTW...
    integrityshield.io/signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t...
data:
  key1: val1
  key2: val2
  key4: val4
```

Creating configmap with this YAML file should be successful because signature in annotation is valid.

```
$ oc create -f /tmp/test-cm.yaml -n secure-ns
configmap/test-cm created
```

## Supported Platforms

K8s Integrity Shield works as Kubernetes Admission Controller using Mutating Admission Webhook, and it can run on any Kubernetes cluster by design.
We have verified the feasibility on the following platforms:

- [RedHat OpenShift 4.5 and 4.6](https://www.openshift.com/)
- [RedHat OpenShift 4.5 on IBM Cloud (ROKS)](https://www.openshift.com/products/openshift-ibm-cloud)
- [IBM Kuberenetes Service (IKS)](https://www.ibm.com/cloud/container-service/) 1.17.14
- [Minikube v1.19.1](https://kubernetes.io/docs/setup/learning-environment/minikube/)
