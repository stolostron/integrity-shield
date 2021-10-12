# integrity-shield
Integrity Shield is a tool for built-in preventive integrity control for regulated cloud workloads. It provides signature-based assurance of integrity for Kubernetes resources at cluster side.  

Integrity Shield works with OPA/Gatekeeper, verifies if the requests attached a signature, and blocks any unauthorized requests according to the constraint before actually persisting in etcd. 

Integrity Shield's capabilities are
- Allow to deploy authorized Kubernetes manifests only
- Zero-drift in resource configuration unless whitelisted
- Perform all integrity verification on cluster (admission controller, not in client side)
- Handle variations in application packaging and deployment (Helm /Operator /YAML / OLM Channel) with no modification in app installer
- Continuous resource monitoring

![Scenario](./docs/new-ishield-scenario.png)


### Integrity Shield API

Integrity shield api includes the main logic to verify admission requests. 
Integrity shield api receives a k8s resource from OPA/Gatekeeper, validates the resource which is included in the admission request based on the profile and sends the verification result to OPA/Gatekeeper.
Integrity shield api uses [k8s-manifest-sigstore](https://github.com/sigstore/k8s-manifest-sigstore) internally to verify k8s manifest.

You can enable the protection by integrity shield with a few simple steps.
Please see [Usage](./shield/README.md).

### Gatekeeper Constraint
Integrity shield works with OPA/Gatekeeper by installing ConstraintTemplate(`template-manifestintegrityconstraint.yaml` ).
We use [constraint framework](https://open-policy-agent.github.io/gatekeeper/website/docs/howto/#constraints) of OPA/Gatekeeper to define the resources to be protected.

For example, the following snippet shows an example definition of protected resources in a namespace. 
```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: ManifestIntegrityConstraint
metadata:
  name: deployment-constraint
spec:
  match:
    kinds:
    - kinds: ["Deployment"]
      apiGroups: ["apps"]
    namespaces:
    - "sample-ns"
  parameters:
    constraintName: deployment-constraint
    action:
      admissionControl:
        enforce: true
      audit:
        inform: true
    objectSelector:
    - name: sample-app
    signers:
    - signer@signer.com
    ignoreFields:
    - objects:
      - kind: Deployment
      fields:
      - spec.replicas
```
`ManifestIntegrityConstraint` resource includes the parameters field. In the parameters field, you can configure the profile for verifying resources such as ignoreFields, signers, and so on.

### Observer 
Integrity shield observer continuously monitors Kubernetes manifest integrity.
It periodically verifies resources on the cluster using [k8s-manifest-sigstore](https://github.com/sigstore/k8s-manifest-sigstore) internally and exports results to ManifestIntegrityState resources.  
For example, the following snippet shows an example of audit result based on one ManifestIntegrityConstraint resource. You can see there is one invalid deployment resource in sample-ns.

```yaml
apiVersion: apis.integrityshield.io/v1
kind: ManifestIntegrityState
metadata:
  creationTimestamp: '2021-10-11T09:01:26Z'
  generation: 16
  labels:
    integrityshield.io/verifyResourceIgnored: 'false'
    integrityshield.io/verifyResourceViolation: 'true'
  name: deployment-constraint
  namespace: integrity-shield-operator-system
spec:
  constraintName: deployment-constraint
  nonViolations: null
  observationTime: '2021-10-11 10:16:27'
  totalViolations: 1
  violation: true
  violations:
    - apiGroup: apps
      apiVersion: v1
      kind: Deployment
      name: sample-app
      namespace: sample-ns
      result: >-
        failed to verify signature: signature verification failed: error occured
        while verifying image
        `sample-image-registry/sample-app-deploy-signature:0.0.1`; no
        matching signatures:
```


### Admission Controller
You can use an admission controller instead of OPA/Gatekeeper.  
In this case, you can decide which resources to be protected in the custom resource called `ManifestIntegrityProfile` instead of OPA/Gatekeeper constraint.

The following snippet is an example of `ManifestIntegrityProfile`.
```yaml
apiVersion: apis.integrityshield.io/v1alpha1
kind: ManifestIntegrityProfile
metadata:
  name: profile-configmap
spec:
  match:
    kinds:
    - kinds:
      - ConfigMap
    namespaces:
    - sample-ns
  parameters:
    constraintName: deployment-constraint
    ignoreFields:
    - fields:
      - data.comment
      objects:
      - kind: ConfigMap
    signers:
    - signer@signer.com
```
Integrity shield with its own admission controller can be installed by this operator cr [apis_v1_integrityshield_ac.yaml](https://github.com/open-cluster-management/integrity-shield/blob/master/integrity-shield-operator/config/samples/apis_v1_integrityshield_ac.yaml).

### Quick Start
See [Quick Start](docs/README_QUICK.md)

## Supported Platforms

IShield can be deployed with operator. We have verified the feasibility on the following platforms:

[RedHat OpenShift 4.7.1 and 4.9.0](https://www.openshift.com)  
[Kind Cluster v1.19.7 and v1.21.1](https://kind.sigs.k8s.io)