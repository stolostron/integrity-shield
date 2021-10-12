# Manifest Integrity Constraint

## Create Manifest Integrity Constraint
You can define which resources should be protected with signature by Integrity Shield.
Custom resource `ManifesetIntegrityConstraint` (MIC) is created to enable the protection.
This constraint uses gatekeeper framework so `match` field should be defined according to [gatekeeper framework](https://open-policy-agent.github.io/gatekeeper/website/docs/howto/).
In `parameters` field, you can define signer configuration, allow patterns, constraint action mode and so on.
The example below shows a definition to protect ConfigMap resource in `sample-ns` namespace.

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: ManifestIntegrityConstraint
metadata:
  name: configmap-constraint
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["ConfigMap"] 
    namespaces:
    - "sample-ns"
  parameters:
    constraintName: configmap-constraint
    action:
      admissionControl:
        enforce: false
      audit:
        inform: true
    signers:
    - sample@signer.com
```


## Parameter field
### Signers
Signer should be defined in each constraints.  
For example, by the below constraint, the resources defined in the match field in constraint must have signature of "sample@signer.com."
```yaml
  parameters:
    signers:
    - sample@signer.com
```

### SignatureRef
If K8s manifest is signed using a bundled OCI image, you can specify the image signature as follows.
```yaml
  parameters:
    signatureRef:
      imageRef: sample-image-registry/sample-configmap-signature:0.1.0
```

### KeyConfigs
If you use PGP, x509 or cosign keyed signing type, 
secret name must be specified in this key configuration. 

```yaml
  parameters:
    keyConfigs:
    - keySecretName: signer-pubkey
      keySecretNamespace: integrity-shield-operator-system
```



### InScopeObjects
In this field, you can define resources should be protected with signature by Integrity Shield **in detail**.
For example, by the below MIC, a ConfigMap resource named `sample-cm` in sample-ns is protected.
```yaml
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["ConfigMap"] 
    namespaces:
    - "sample-ns"
  parameters:
    objectSelector:
    - name: sample-cm
```
### SkipObjects
The resources covered by the rule above cannot be created/updated without signature, but you may want to define cases for allowing requests in certain situations.

You can use `skipObjects` to define a condition for allowing some requests that match this rule.  
For example, by the below constraint, all ConfigMap resources are protected in this namespace, but a ConfigMap named ignored-cm is allowed without signature.

```yaml
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["ConfigMap"] 
    namespaces:
    - "sample-ns"
  parameters:
    skipObjects:
    - kind: ConfigMap
      name: ignored-cm
```

### InScopeUsers
You can also set rules to override allow patterns.
For example, by the below rule, all requests about ConfigMap in sample-ns are verified with signature even if the requests are created/updated by whitelisted ServiceAccount.
```yaml
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["ConfigMap"] 
    namespaces:
    - "sample-ns"
  parameters:
    inScopeUsers:
    - users:
      - system:admin
```

### SkipUsers
The resources covered by the rule above cannot be created/updated without signature, but you may want to define cases for allowing requests in certain situations.

You can use skipUsers to define a condition for allowing some requests that match this rule.  
For example, by the below constraint, all requests of Policy are protected, but only requests by "system:serviceaccount:open-cluster-management-agent:*" ServiceAccount is allowed without signature.
```yaml
  match:
    kinds:
    - apiGroups:
      - policy.open-cluster-management.io
      kinds:
      - Policy
  parameters:
    skipUsers:
    - users:
      - system:serviceaccount:open-cluster-management-agent:*
```

### ImageProfile
By setting the imageProfile field as follows, images referenced in K8s manifests such as Deployment can be protected with a signature.
```yaml
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment"] 
    namespaces:
    - "sample-ns"
  parameters:
   imageProfile:
       match:
       - "sample-registry/sample-image:*"
```

### Define allow change patterns

You can also set rules to allow some changes in the resource even without valid signature. For example, changes in attribute `data.comment1` in a ConfigMap `protected-cm` is allowed.

```yaml
  parameters:
    ignoreAttrs:
    - fields:
      - data.comment1
      objects:
      - name: protected-cm
        kind: ConfigMap
```

### Run mode
- **admissionControl**: If enforce is true, the admission requests about resources defined in the constraint are enforced, so the admission request is blocked if the resource is invalid. If enforce is false, the admission request is allowed even if the resource is not valid.
- **audit**:  If inform is true, the audit results for the constraint is exported to ManifestIntegrityStatus resource as usual. If inform is false, the results will be exported, but the ManifestIntegrityStatus resource will be labeled with ignored=true.
```yaml
  parameters:
    action:
      admissionControl:
        enforce: false
      audit:
        inform: true
```