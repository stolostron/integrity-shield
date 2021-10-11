

# Custom Resource: IntegrityShield

Integrity Shield can be deployed with operator. You can configure IntegrityShield custom resource to define the configuration of IShield.

## RequestHandlerConfig
### DefaultConstraintAction
Integrity shield enforce/monitor resources according to ManifestIntegrityConstraint. 
In defaultConstraintAction, you can set whether to ignore the audit result and to enforce admission request or not by default.
```yaml
    defaultConstraintAction:
      audit:
        inform: true
      admissionControl:
        enforce: false
```

### SideEffect
Integrity Shield generates an event by default when it blocks a request because it fails to verify the signature. 
You can disable the generation of the event by setting false here.
```yaml
    sideEffect: 
      createDenyEvent: true
```

### RequestFilterProfile
The requests related to internal cluster behavior should be listed here because these requests are not mutation and should be allowed even if they do not have signature.

```yaml
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

## UseGatekeeper
When you use Gatekeeper as admission controller, this parameter should be set `true`.
```yaml
  useGatekeeper: true
```

## Default setting in rego policy
Integrity shield uses rego policy to work with Gatekeeper.
In default setting field, enforce mode and unprocessed requests can be defined.
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

## Observer
### Interval
Integrity shield observer periodically validates the resources installed in the cluster. The interval can be set here. The default is 5 minutes.
```
  observer:
    interval: '5'
```

