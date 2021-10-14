## Install IShield to a local cluster (minikube)

This section describe the steps for deploying Integrity Shield (IShield) on your local minikube cluster via `oc` or `kubectl` CLI commands. 

1. Retrive the source from `integrity-enforcer` Git repository.

    git clone this repository and moved to `integrity-enforcer` directory

    ```
    $ git clone https://github.com/open-cluster-management/integrity-shield.git
    $ cd integrity-shield
    $ pwd /home/repo/integrity-enforcer
    ```
    In this document, we clone the code in `/home/repo/integrity-enforcer`.
    
2.  Prepare a namespace to deploy Integrity Shield. 

    The following command uses `integrity-shield-operator-system` as default namespace for Integrity Shield. 
    ```
    make create-ns
    ```
    We swtich to `integrity-shield-operator-system` namespace.
    ```
    oc project integrity-shield-operator-system
    ```
3.  Prepare a private registry for hosting IShield container images, if not already exist.

    The following example create a private local container image registry to host the IShield container images.
    ```
    $ make create-private-registry
`   ```

4. Define a public key secret for verifying signature by Integrity Shield.

    Integrity Shield requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.  Integrity Shield supports X509 or PGP key for signing resources.

    By default, Integrity Shield provides a key setup. 
    
    If you would like to use default key setup, the following command creates a public key secret for verifying signature
    ```
    $ make create-key-ring
    ```

    If you would like to use your own key, please follow the steps in [doc](README_VERIFICATION_KEY_SETUP.md) to generate a one:

    Once you have the encoded content of a verification key `/tmp/pubring.gpg`, embed it to `/tmp/keyring-secret.yaml` as follows.

      ```yaml
       apiVersion: v1
       kind: Secret
       metadata:
         name: keyring-secret
         type: Opaque
       data:
         pubring.gpg: mQGNBF5nKwIBDADIiSiWZkD713UWpg2JBPomrj/iJRiMh ...
      ```

    Create `keyring-secret` in a namespace ``integrity-shield-operator-system`` in the cluster.

    ```
    $ oc create -f  /tmp/keyring-secret.yaml -n `integrity-shield-operator-system`
    ```

5. Define which signers (identified by email) should sign the resources in a specific namespace.

    If you use default key setup, the following command setup signers. 
    ```
    make setup-tmp-cr
    ```

    If you use your own key setup, configure `signerConfig` and `keyConfig` in the following `integrity-shield` Custom Resource file:

    Edit [`config/samples/apis_v1alpha1_integrityshield.yaml`](../integrity-shield-operator/config/samples/apis_v1alpha1_integrityshield.yaml) to specify a signer for a namespace `secure-ns`.

    Example below shows a signer `SampleSigner` identified by email `signer@enterprise.com` is configured to sign rosources to be protected in any namespace.

    ```yaml
    signerConfig:
      policies:
      - namespaces:
        - "*"
        signers:
        - "SampleSigner"
      - scope: "Cluster"
        signers:
        - "SampleSigner"
      signers:
      - name: "SampleSigner"
        keyConfig: sample-signer-keyconfig
        subjects:
        - email: "sample_signer@signer.com"
    keyConfig:
    - name: sample-signer-keyconfig
      secretName: keyring-secret
    ```


6. Install Integrit Shield to a cluster

    Integrity Shield can be installed to cluster using a series of steps which are bundled in make commands.
    
    Before execute the make command, setup local environment as follows:
    - `ISHIELD_ENV` <local: means that we deploy IShield to a local cluster like Minikube>
    - `ISHIELD_REPO_ROOT=<set absolute path of the root directory of cloned integrity-shield source repository>`
    - `KUBECONFIG=~/kube/config/minikube`  (for deploying IShield on minikube cluster)

    `~/kube/config/minikube` is the Kuebernetes config file with credentials for accessing a cluster via `kubectl`.

    The following example shows how to set up a local envionement.  

    ```
    $ export ISHIELD_ENV=local
    $ export ISHIELD_REPO_ROOT=/home/repo/integrity-enforcer
    $ export KUBECONFIG=~/kube/config/minikube
    ``` 
    In this document, we clone the code in `/home/repo/integrity-enforcer`.

    Execute the following make commands to build Integrity Shield container images and pushes them to a local private container image registry..
    ```
    $ cd integrity-shield
    $ make build-images
    $ make push-images-to-local
    ```

    Execute the following make commands to deploy Integrity Shield in a cluster.

    ```
    $ make install-crds
    $ make install-operator
    ```

    If you use default key setup, the following command create Integrity Shield CR in cluster. 
    ```
    $ make create-tmp-cr
    ```

    If you use your own key setup, the following command create Integrity Shield CR in cluster. 
    ```
    $ make create-cr
    ```

7. Confirm if `integrity-shield` is running successfully in a cluster.
    
    Check if there are two pods running in the namespace `integrity-shield-operator-system`: 
        
    ```
    $ oc get pod -n integrity-shield-operator-system
    integrity-shield-operator-c4699c95c-4p8wp   1/1     Running   0          5m
    integrity-shield-server-85c787bf8c-h5bnj    2/2     Running   0          82m
    ```

8. Clean up `integrity-shield` from a cluster

    Execute the following script to remove all resources related to IShield deployment from cluster.
    ```
    $ cd integrity-shield
    $ make delete-tmp-cr
    $ make delete-operator
    ```
