

# Custom Resource: IntegrityShield

Integrity Shield can be deployed with operator. You can configure IntegrityShield custom resource to define the configuration of Integrity Shield.
Please update IntegrityShield custom resource as necessary.

1. [General configuration of Integrity Shield](#general-configuration-of-integrity-shield)
2. [Observer configuration](#observer-configuration)
3. [Gatekeeper-related settings](#gatekeeper-related-settings)
4. [Admission controller configuration](#admission-controller-configuration)

## General configuration of Integrity Shield 

### Define default run mode
Integrity shield enforce/monitor resources according to ManifestIntegrityConstraint. The behavior when Integrity Shield verify resources is defined in action field. See [Define run mode](README_CONSTRAINT.md#define-run-mode).  
When you want to change the default value, please edit here.
```yaml
  requestHandlerConfig: |
    mode: detect
```

### Enable/Disable side effect
Integrity Shield generates an event by default when it blocks a request because it fails to verify the signature. 
You can disable the generation of the event by setting false here.
```yaml
  requestHandlerConfig: |
    sideEffect: 
      createDenyEvent: true
```

### Define allow patterns
The requests related to internal cluster behavior should be listed here because these requests are not mutation and should be allowed even if they do not have signature.

We prepared this profile to allow internal operations that occur in a typical Kubernetes cluster. Please update it as necessary.

```yaml
  requestHandlerConfig: |
    requestFilterProfile: 
      skipObjects:
      - kind: ConfigMap
        name: kube-root-ca.crt
      ignoreFields:
      - fields:
        - spec.host
        objects:
        - kind: Route
      - fields:
        - metadata.namespace
        objects:
        - kind: ClusterServiceVersion
      - fields:
        - metadata.labels.app.kubernetes.io/instance
        - metadata.managedFields.*
        - metadata.resourceVersion
        ...
```

### Define images
When you want to use your own images, you can set images like this.
```yaml
  shieldApi:
    image: quay.io/stolostron/integrity-shield-api
  observer: 
    image: quay.io/stolostron/integrity-shield-observer
```
Image version will automatically be set to the same version as Integrity Shield. If you want to use a different tag, you can define the tag as follows.
```yaml
  shieldApi:
    image: sample-image-registry/integrity-shield-api
    tag: 0.1.0
```

### Define secret for private manifest regsitry 
If you use private OCI registry, please set secret name which includes Docker credentials.
```yaml
  registryConfig: 
    manifestPullSecret: regcred
```

## Observer configuration
### Enable observer
If you don't want to install observer, set false here.
```yaml
  observer: 
    enabled: true
```

### Define audit interval
Integrity shield observer periodically validates the resources installed in the cluster. The interval can be set here. The default is 5 minutes.
```
  observer:
    interval: '5'
```

## Gatekeeper-related settings
### Enable linkage with gatekeeper
When you use Gatekeeper as admission controller, this parameter should be set `true`.
```yaml
  useGatekeeper: true
```

### Define rego policy
Integrity shield uses rego policy to work with Gatekeeper.
- enforce mode: If you want to use Integrity Shield on detection mode, please change this field to "detect."
- skip kinds: You can define Kinds that do not need to be processed by Integrity Shield.
- exclude_namespaces: All resources in the listed namespace will not be processed by Integrity Shield.

```yaml
################### 
# Default setting #
###################

# Mode whether to deny a invalid request [enforce/detect]
enforce_mode = "enforce"

# kinds to be skipped
skip_kinds = [
          {
            "kind": "Event"
          },
          {
            "kind": "Lease"
          },
          {
            "kind": "Endpoints"
          },
          {
            "kind": "TokenReview"
          },
          {
            "kind": "SubjectAccessReview"
          },
          {
            "kind": "SelfSubjectAccessReview"
          }
        ]

# exclude namespaces
exclude_namespaces = [
                      "kube-node-lease",
                      "kube-public",
                      "kube-storage-version-migrator-operator",
                      "kube-system",
                      "open-cluster-management",
                      ....
                      "openshift-vsphere-infra"
                  ]
```

## Admission controller configuration
If you want to try Integrity shield with its own admission controller, you can install it by this IntegrityShield custom resource [apis_v1_integrityshield_ac.yaml](https://github.com/stolostron/integrity-shield/blob/master/integrity-shield-operator/config/samples/apis_v1_integrityshield_ac.yaml).

### Define admission controller setting
- allow: You can define Kinds that do not need to be processed by Integrity Shield.
- mode: If you want to use Integrity Shield on detection mode, please change this field to "detect."
- inScopeNamespaceSelector: You can define which namespace is not checked by Integrity Shield. All resources in the exclude namespaces will not be processed by Integrity Shield.

```yaml
 admissionControllerConfig: |
    allow:
      kinds:
      - kind: Event
      - kind: Lease
      - kind: Endpoints
      - kind: TokenReview
      - kind: SubjectAccessReview
      - kind: SelfSubjectAccessReview
    mode: enforce
    sideEffect: 
      updateMIPStatusForDeniedRequest: true
    inScopeNamespaceSelector:
      exclude:
      - kube-node-lease
      - kube-public
      - kube-storage-version-migrator-operator
      - kube-system
    ...
```