## Example: Helm Verification

This document describes the steps to protect Helm chart resources with Integrity Shield (IShield).


### Easy 5 Steps for Helm chart installation with IShield verification 

IShield provides protection for Helm chart resources. To protect the Helm chart resources, let's get a manifest of the resources with `helm template` command.

1. Create a manifest of Helm chart resources with `helm template` command, the arguments should be the same as the ones when you execute `helm install` actually.

   ```
    $ helm template --namespace sample-ns sample-app-1 ./sample-chart.tgz --values your_values.yaml --no-hooks > /tmp/sample-chart-manifest.yaml
   ```

2. Create a ResourceSignature for the manifest using a signing script. For more information about resource signing, please see [How to Sign Resources](README_RESOURCE_SIGNATURE.md).

  
   ```
   $ ./scripts/gpg-rs-sign.sh <SAMPLE_SIGNER_EMAIL> /tmp/sample-chart-manifest.yaml /tmp/sample-chart-manifest-rs.yaml
   ```

3. Create a ResourceSigningProfile for the Helm resources by the script.

   
   ```
   $ generate_rsp.sh <ARGS: TODO FIX THIS> > /tmp/sample-chart-rsp.yaml
   ```

   `/tmp/sample-chart-rsp.yaml` is generated, and the content is something like this.

   ```
   apiVersion: apis.integrityshield.io/v1alpha1
   kind: ResourceSigningProfile
   metadata:
     name: ac-test-chart-rsp
   spec:
     protectRules:
     - match:
       - kind: ServiceAccount
         name: sample-app-1-sample-chart
       - kind: Secret
         name: sample-app-1-sample-chart-secret
   ```
   
4. Once ResourceSignature and ResourceSigningProfile are ready, deploy them in the namespace which you will use for Helm chart installation. 
   
   ```
   $ oc create -n sample-ns -f /tmp/sample-chart-manifest-rs.yaml
   $ oc create -n sample-ns -f /tmp/sample-chart-rsp.yaml
   ```

5. It's time to install the Helm chart!

   ```
   $ helm install sample-app-1 -n sample-ns ./sample-chart.tgz --values your_values.yaml
   NAME: sample-app-1
   LAST DEPLOYED: Fri Oct  9 15:19:06 2020
   NAMESPACE: sample-ns
   STATUS: deployed
   REVISION: 1
   NOTES:
   1. Get the application URL by running these commands:
   export POD_NAME=$(kubectl get pods --namespace sample-ns -l "app.kubernetes.io/name=sample-chart,app.kubernetes.io/instance=sample-app-1" -o jsonpath="{.items[0].metadata.name}")
   echo "Visit http://127.0.0.1:8080 to use your application"
   kubectl --namespace sample-ns port-forward $POD_NAME 8080:80 
   ```

   Of course you can deploy the chart resources with the next command, but please note that you cannot `helm delete` in this case.

   ```
   $ oc create -n sample-ns -f /tmp/sample-chart-manifest.yaml
   ```

