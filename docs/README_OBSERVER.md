# How to check Kubernetes resource integrity on cluster

Integrity shield observer continuously monitors Kubernetes resource integrity on cluster. 
Observer verifies resources according to constraints and exports the results to ManifestIntegrityState resources.

## Create Manifest Integrity Constraint
Please see [Manifest Integrity Constraint](README_CONSTRAINT.md)

Here, we use the constraint below.

```
$ kubectl get constraint configmap-constraint -o yaml
```
```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: ManifestIntegrityConstraint
metadata:
  creationTimestamp: "2021-10-12T02:29:28Z"
  generation: 1
  name: configmap-constraint
  resourceVersion: "10900882"
  uid: 8a16c3d9-5fa7-471f-be51-fefb3c454f33
spec:
  match:
    kinds:
    - apiGroups:
      - ""
      kinds:
      - ConfigMap
    namespaces:
    - sample-ns
  parameters:
    action:
      admissionControl:
        enforce: false
      audit:
        inform: true
    constraintName: configmap-constraint
    ignoreFields:
    - fields:
      - data.comment
      objects:
      - kind: ConfigMap
    objectSelector:
    - name: sample-cm
    signers:
    - sample@signer.com
    skipObjects:
    - kind: ConfigMap
      name: openshift-service-ca.crt
```
## Check Manifest Integrity State
1. Check audit result for all constraints on cluster with this command.
```
$ kubectl get mis --show-labels -n integrity-shield-operator-system
```
You can see whether each constraint has violations by checking `integrityshield.io/verifyResourceViolation` label.
In this case, you can see that some resources defined in configmap-constraint are in invalid state because `integrityshield.io/verifyResourceViolation` label is true.
```
NAME                        AGE   LABELS
configmap-constraint        4d    integrityshield.io/verifyResourceIgnored=false,integrityshield.io/verifyResourceViolation=true
deployment-constraint       17h   integrityshield.io/verifyResourceIgnored=false,integrityshield.io/verifyResourceViolation=false
```
2. Check verification result on per constraint
You can see which resources are violated from ManifestIntegrityState.

In this example, there are four configmaps in sample-ns and sample-cm is not signed. The totalViolations field indicates that there is one violation in configmap-constraint.

```
$ kubectl get mis -n integrity-shield-operator-system configmap-constraint -o yaml
```
```yaml
apiVersion: apis.integrityshield.io/v1
kind: ManifestIntegrityState
metadata:
  creationTimestamp: "2021-10-08T01:49:45Z"
  labels:
    integrityshield.io/verifyResourceIgnored: "false"
    integrityshield.io/verifyResourceViolation: "true"
  name: configmap-constraint
  namespace: integrity-shield-operator-system
  resourceVersion: "10844495"
spec:
  constraintName: configmap-constraint
  nonViolations:
  - apiGroup: ""
    apiVersion: ""
    kind: ConfigMap
    name: game-demo
    namespace: sample-ns
    result: 'singed by a valid signer: sample@signer.com'
    sigRef: sample-image-registry/sample-cm-signature:0.0.1
    signer: rkudo@redhat.com
  - apiGroup: ""
    apiVersion: ""
    kind: ConfigMap
    name: kube-root-ca.crt
    namespace: sample-ns
    result: not protected
  - apiGroup: ""
    apiVersion: ""
    kind: ConfigMap
    name: openshift-service-ca.crt
    namespace: sample-ns
    result: not protected
  observationTime: "2021-10-12 02:31:27"
  totalViolations: 1
  violation: true
  violations:
  - apiGroup: ""
    apiVersion: v1
    kind: ConfigMap
    name: sample-cm
    namespace: sample-ns
    result: 'failed to verify signature: failed to get signature: `cosign.sigstore.dev/message`
      is not found in the annotations'
```