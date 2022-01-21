# Admission Controller for k8s manifest verification

You can use an admission controller instead of OPA/Gatekeeper.  
### Install
Integrity shield with its own admission controller can be installed by this operator cr [apis_v1_integrityshield_ac.yaml](https://github.com/stolostron/integrity-shield/blob/master/integrity-shield-operator/config/samples/apis_v1_integrityshield_ac.yaml).

### Enable protection
You can decide which resources to be protected in the custom resource called `ManifestIntegrityProfile` instead of OPA/Gatekeeper constraint.

The following snippet is an example of `ManifestIntegrityProfile`.
In this example, we installed the following profile to protect ConfigMap in sample-ns.

```
apiVersion: apis.integrityshield.io/v1
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


First, creating a ConfigMap in sample-ns without signature will be blocked.
```
$ kubectl create -n sample-ns -f sample-configmap.yaml
Error from server (no signature found): error when creating "sample-configmap.yaml": admission webhook "k8smanifest.sigstore.dev" denied the request: no signature found
```

Then, sign the ConfigMap YAML manifest with `kubectl sigstore sign` command and creating it will pass the verification.
```
$ kubectl sigstore sign -f sample-configmap.yaml -i <K8S_MANIFEST_IMAGE>
...

$ kubectl create -n sample-ns -f sample-configmap.yaml.signed
configmap/sample-cm created
```

After the above, any runtime modification without signature will be blocked.
```
$ kubectl patch cm -n sample-ns sample-cm -p '{"data":{"key1":"val1.1"}}'
Error from server (diff found: {"items":[{"key":"data.key1","values":{"after":"val1","before":"val1.1"}}]}): admission webhook "k8smanifest.sigstore.dev" denied the request: diff found: {"items":[{"key":"data.key1","values":{"after":"val1","before":"val1.1"}}]}
```