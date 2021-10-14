# Define Protected Resources


## Create Resource Signing Profile
You can define which resources should be protected with signature by Integrity Shield.
For resources in a namespace, custom resource `ResourceSigningProfile` (RSP) is created in the same namespace.
The example below shows a definition to protect ConfigMap and Service resource in `secure-ns` namespace.

```yaml
apiVersion: apis.integrityshield.io/v1alpha1
kind: ResourceSigningProfile
metadata:
  name: sample-rsp
  namespace: secure-ns
spec:
  protectRules:
  - match:
    - kind: ConfigMap
    - kind: Service
```

You can create these resource by

```
oc apply -f sample-rsp.yaml -n secure-ns
```

This profile become available instantly after creation, and any further incoming admission requests that match this profile will be evaluated by signature verification in IShield.


## Rule Syntax
You can list rules to define protect resources.
Rule has `match` and `exclude` fields.
The rules can be defined with the fields `name, operation, apiVersion, apiGroup, kind, username`.
In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard.

If you want to exclude some resources from matched resources, you can set rules in `exclude` field.

For example, the rule below covers any ConfigMap except name `unprotected-cm` and any resources in apiGroup `rbac.authorization.k8s.io` in the same namespace.

```yaml
protectRules:
- match:
  - kind: ConfigMap
  exclude:
  - kind: ConfigMap
    name: unprotected-cm
- match:
  - apiGroup: rbac.authorization.k8s.io
```

Another example below is the rule covers any resources in the same namespace.

```yaml
protectRules:
- match:
  - kind: "*"
```


## Define allow patterns

The resources covered by the rule above cannot be created/updated without signature, but you may want to define cases for allowing requests in certain situations.

You can use `ignoreRules` to define a condition for allowing some requests that match this rule.
For example, by the below RSP, all namespaced requests are protected in this namespace, but only requests by `secure-operator` ServiceAccount is allowed without signature.

```yaml
protectRules:
- match:
  - kind: "*"
ignoreRules:
- match:
  - username: "system:serviceaccount:secure-ns:secure-operator"
```

## Define force check patterns (override allow pattern)
You can also set rules to override allow patterns.
For example, the following RSP will protect all requests in the namespace except ones by `secure-operator` ServiceAccount, but only the requests that are Secret kind will be protected with signature because it is specified in `forceCheckRules`.


```yaml
protectRules:
- match:
  - kind: "*"
ignoreRules:
- match:
  - username: "system:serviceaccount:secure-ns:secure-operator"
forceCheckRules:
- match:
  - kind: "Secret"
```

## Define allow change patterns

You can also set rules to allow some changes in the resource even without valid signature. For example, changes in attribute `data.comment1` in a ConfigMap `protected-cm` is allowed.

```yaml
ignoreAttrs:
- attrs:
  - data.comment1
  match:
  - name: protected-cm
    kind: ConfigMap
```


## Cluster scope
Also for cluster-scope resources, you can use RSP to define protection rules.
The only difference between "Namespaced" and "Cluster" scope in RSP is name condition.
To avoid conflict of rules defined in multiple RSPs in different NS, a rule for Cluster scope resource must be set with concrete resource name condition.
The example below shows how to protect ClusterRoleBinding with its name.

```yaml
apiVersion: apis.integrityshield.io/v1alpha1
kind: ResourceSigningProfile
metadata:
  name: sample-rsp
spec:
  protectRules:
  - match:
    - kind: ClusterRoleBinding
      name: sample-crb
```

if the `name` is not specified or value for `name` has any wildcard "*", then the rule does not match with any requests.

## Two types of RSP

There are two types in RSP.
  1. per-namespace RSP
  2. IShield namespace RSP
1, per-namespace RSP will be created and managed by user, and it has different lifecycle from the one of IShield itself. 
2, IShield namespace RSP, this is managed by IShield operator. It is defined in IShield CR, and operator will reconcile it.

All syntax around rules are exactly same between these 2 types, but the namespace scope is different.

per-NS RSP, is basically used only for requests in the same namespace.
If per-NS RSP is created in `secure-ns`, then this profile is available only in `secure-ns`.

IShield NS RSP, is created in IShield namespace, but it will be evaluated with some other namespaced requests. 
This target namespace is defined in `targetNamespaceSelector` in RSP spec.

The following is an example of IShield NS RSP definition in IShield CR.
It is available for requests in `secure-ns` and `test-ns`.

```yaml
spec:
  resourceSigningProfiles:
  - name: multi-ns-rsp
    targetNamespaceSelector:
      include:
      - secure-ns
      - test-ns
    protectRules:
    - match:
      - kind: ConfigMap
```

for this `targetNamespaceSelector`, label selector also can be used instead of namespace list, like below.
This RSP will protect ConfgiMap in all namespaces that have `sampleNamespaceLabel: foo` or `sampleNamespaceLabel: bar` labels.

```yaml
spec:
  resourceSigningProfiles:
  - name: multi-ns-rsp
    targetNamespaceSelector:
      labelSelector:
        matchExpressions:
        - key: "sampleNamespaceLabel"
          operator: In
          value: ["foo", "bar"]
    protectRules:
    - match:
      - kind: ConfigMap
```


<!-- ## Delete/Disable RSP

RSP and CRSP have two lifecycle flags `disabled` and `delete`. Those fields are `false` by default.

If `disabled` is set to `true`, the RSP (CRSP) becomes invalid and ignored when checking signature (This implies no RSP is defined in the namespace). When you set it to `false` back, the RSP will become effective again.

When you want to delete RSP, set `delete` to `true`, then IShield will delete RSP (CRSP). RSP and CRSP cannot be deleted directly, so need to set this flag when you want to delete then.

```
apiVersion: apis.integrityshield.io/v1alpha1
kind: ResourceSigningProfile
metadata:
  name: sample-rsp
  namespace: secure-ns
spec:
  disabled: false
  delete: false
``` -->

## Example of RSP

The whole RSP is represented like this. (this is example of per-namespace RSP.)
```yaml
apiVersion: apis.integrityshield.io/v1alpha1
kind: ResourceSigningProfile
metadata:
  name: sample-rsp
  namespace: secure-ns
spec:
  protectRules:
  - match:
    - kind: ConfigMap
    - kins: Secret
    exclude:
    - kind: ConfigMap
      name: unprotected-cm
  - match:
    - apiGroup: rbac.authorization.k8s.io
  ignoreRules:
  - username: system:serviceaccount:secure-ns:secure-operator
  ignoreAttrs:
  - match:
    - name: protected-cm
      kind: ConfigMap
    attrs:
    - data.comment1
```
