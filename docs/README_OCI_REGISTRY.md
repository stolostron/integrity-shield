# Setup for using private OCI Registry

Integrity Shield supports various signing and verification types for Kubernetes manifests.
You can use the signature stored in the OCI registry for Kubernetes manifest protection.

When you use a private OCI Registry, you need to provide permission to Integrity Shield for pulling manifest images and signature images.
 
This document will guide you through:
- Storing Docker credentials as a Kubernetes Secret
- Configuring IntegrityShield Custom Resource to specify secret

### Prerequisite
You need to authenticate with a registry in order to pull a private image.
After login the private registry, you can see authorization tokens in  `config.json` file. 

```
cat ~/.docker/config.json
```
The output is similar to this:
```
{
  "auths": {
    "gcr.io": {
      "auth": "b2F...1dG"
    },
    "https://index.docker.io/v1/": {
      "auth": "c3R...zE2"
    }
  }
}
```
### Store Docker credentials as a Kubernetes Secret

To copy docker credentials into Kubernetes, set secret name and the path to your docker config.json file, then execute the following command. 
This secret should be created in `integrity-shield-operator-system` namespace.
```
kubectl create secret generic <secret name> \
-n integrity-shield-operator-system \
--from-file=config.json=<path/to/.docker/config.json>
```

### Configure IntegrityShield Custom Resource
You need to set secret name in IntegrityShield CR before installing Integrity Shield. In order to verify Kubernetes manifest using signature image, the Docker credentials secret should be mounted on Integrity Shield pod.

```yaml
apiVersion: apis.integrityshield.io/v1
kind: IntegrityShield
metadata:
  name: integrity-shield
spec:
  registryConfig: 
    manifestPullSecret: <secret name>
```