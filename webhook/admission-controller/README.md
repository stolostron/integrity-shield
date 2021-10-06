# k8s admission controller for k8s manifest verification

This is an admission controller for verifying k8s manifest with sigstore signing.
You can use this admission controller instead of OPA/Gatekeeper.

## Setup
You can set up the admission controller just by the following commands.

Please specify an image which you can push there and which can be pulled from the cluster as <YOUR_IMAGE_NAME>.

```
# Move to admission-controller directory
$ pwd 
/integrity-shield/webhook/admission-controller

# Build & push an image of admission controller into a registry
$ make build IMG=<YOUR_IMAGE_NAME>

# Deploy an admission controller
$ make deploy IMG=<YOUR_IMAGE_NAME>

# Deploy configmaps for the admission controller
$ kubectl create -f resource/admission-controller-config.yaml
$ kubectl create -f ../integrity-shield-server/resource/request-handler-config.yaml
```
After successful installation, you will see the following resources.
```
$ kubectl get all -n k8s-manifest-sigstore                                  
NAME                                          READY   STATUS    RESTARTS   AGE
pod/k8s-manifest-validator-798fc4bb55-9jpkp   1/1     Running   0          18h

NAME                                   TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
service/k8s-manifest-webhook-service   ClusterIP   10.96.252.175   <none>        443/TCP   18h

NAME                                     READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/k8s-manifest-validator   1/1     1            1           18h

NAME                                                DESIRED   CURRENT   READY   AGE
replicaset.apps/k8s-manifest-validator-798fc4bb55   1         1         1       18h
```


### Usage

The admission webhook is configured to receive requests in namespaces that have a label "k8s-manifest-sigstore=true" .

This command shows which namespace is targeted by the admission controller.
```
$ kubectl get ns -L k8s-manifest-sigstore
NAME                    STATUS   AGE    K8S-MANIFEST-SIGSTORE
default                 Active   22d
k8s-manifest-sigstore   Active   16s
kube-system             Active   22d
sample-ns               Active   19d    true
```
To enable checking requests by integrity shield, `ManifestIntegrityProfile` should be defined.
In this example, we installed the following profile to protect ConfigMap in sample-ns.

```
apiVersion: apis.integrityshield.io/v1
kind: ManifestIntegrityProfile
metadata:
  name: constraint-configmap
spec:
  match:
    kinds:
    - kinds:
      - ConfigMap
    namespaces:
    - sample-ns
  parameters:
    ignoreFields:
    - fields:
      - data.comment
      objects:
      - kind: ConfigMap
    signers:
    - signer@signer.com
```
```
# Deploy CustomResourceDefinition of the profile
$ kubectl create -f resource/manifest_integrity_profile_crd.yaml

# Deploy ManifestIntegrityProfile
$ kubectl create -f resource/example/profile-configmap.yaml
```

First, creating a ConfigMap in a target namespace without signature will be blocked.
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


## Manifest integrity profile
When you use the admission controller instead of OPA/Gatekeeper, you should use this resource instead of constraint of OPA/Gatekeeper.
By installing a resource `ManifestIntegrityProfile`, you can enable the verification by integrity shield.  
Basically, the usage of this resource is the same as the Gatekeeper constraint.

