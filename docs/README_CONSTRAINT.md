# Configuring Integrity Shield Protection
Custom resource `ManifesetIntegrityConstraint`(constraint) is created to enable the protection.

## Define resources to be protected

You can define which resources should be protected with signature by Integrity Shield in `match` field.
ManifesetIntegrityConstraint is based on gatekeeper framework so `match` field should be defined according to [gatekeeper framework](https://open-policy-agent.github.io/gatekeeper/website/docs/howto/).
The example below shows a definition to protect ConfigMap resource in `sample-ns` namespace.

```yaml
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["ConfigMap"] 
    namespaces:
    - "sample-ns"
```

## Define signers
Signer should be defined in each constraints.  
For example, by the below constraint, the resources defined in the match field in constraint must have signature of "sample@signer.com."
```yaml
  parameters:
    signers:
    - sample@signer.com
```

## Define signature used to verify resource.
If K8s manifest is signed using a bundled OCI image, you can specify the image signature as follows.
```yaml
  parameters:
    signatureRef:
      imageRef: sample-image-registry/sample-configmap-signature:0.1.0
```

## Define verification key used to verify resource
If you use PGP, x509 or cosign keyed signing type, 
a secret resource which contains public key and certificates should be setup in a cluster and secret name should be specified in this key configuration. 

```yaml
  parameters:
    keyConfigs:
    - keySecretName: signer-pubkey
      keySecretNamespace: integrity-shield-operator-system
```


## Define run mode
You can change behavior when Integrity Shield verify resources by changing action field.
If mode is set to `enforce`, the admission requests for the resource defined in the constraint are enforced, so the admission request is blocked if the resource is invalid. If mode is `detect`, the admission request is allowed even if the resource is not valid.
```yaml
  parameters:
    action:
      mode: detect
```

## Define target object scope
You can define resources should be protected with signature by Integrity Shield **in detail** by using objectSelector field.
For example, by the below constraint, a ConfigMap resource named `sample-cm` in sample-ns is protected.
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
## Define object to be allowed without signature
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

## Define force check ServiceAccount
You can also set rules to override allow patterns.
For example, by the below rule, all requests for ConfigMap in sample-ns created/updated by `system:admin` ServiceAccount are verified with signature even if system:admin is whitelisted in default rule.
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

## Define allow ServiceAccount
The resources defined in match field cannot be created/updated without signature, but you may want to define cases for allowing requests in certain situations.

You can use skipUsers to define a condition for allowing some requests that match this rule.  
For example, by the below constraint, all requests of Policy are protected, but only requests created/updated by "system:serviceaccount:open-cluster-management-agent:*" ServiceAccount is allowed without signature.
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

### Define image to be protected
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

## Define allow change patterns

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

### Example of ManifesetIntegrityConstraint
The whole ManifesetIntegrityConstraint is like this.

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
      mode: inform
    signers:
    - sample@signer.com
    skipObjects:
    - kind: ConfigMap
      name: ignored-cm
```