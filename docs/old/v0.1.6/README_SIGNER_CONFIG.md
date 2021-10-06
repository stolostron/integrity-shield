## Signer Configuration

### This CR should not be edited directly.
Usually, SignerConfig CR is automatically created/updated using `signerConfig` config in IntegrityShield CR.
Please note that operator would reconcile the resource with the original one and it might remove your direct changes.

### Define signer for each namespaces

SignerConfig is a custom resource to define who can be a valid signer for resources in a namespace or for cluster scope resources.
Only a SignerConfig which is created in IShield namespace (`integrity-shield-operator-system` in this doc) by operator is valid and all other instances are not used by IShield.

To update SignerConfig after IShield deployment, please update the `signerConfig` in IntegrityShield CR.

Example below is to define
- signer `signer-a` is identified when email of subject of signature is `signer@enterprise.com` and the verification key for this subject is included in `keyring-secret` secret specified under `keyConfig`
- signer `signer-a` is approved signer for the resources to be created in namespace `secure-ns`.

For matching signer, you can use the following attributes: `email`, `uid`, `country`, `organization`, `organizationalUnit`, `locality`, `province`, `streetAddress`, `postalCode`, `commonName` and `serialNumber`.


```yaml
  signerConfig:
    policies:
    - namespaces:
      - "secure-ns"
      signers:
      - "signer-a"
    signers:
    - name: "signer-a"
      keyConfig: sample-signer-keyconfig
      subjects:
      - email: "signer@enterprise.com"
  keyConfig:
  - name: sample-signer-keyconfig
    secretName: keyring-secret

```

Updating IShield CR with the above block, the operator will update the SignerConfig resource.

You can define namespace matcher by using `excludeNamespaces`.
For example below, signer `signer-a` can sign resource in `secure-ns` namespace, and another signer `signer-b` can sign resource in all other namespaces except `secure-ns`.

```yaml
spec:
  signerConfig:
    policies:
    - namespaces:
      - secure-ns
      signers:
      - signer-a
    - namespaces:
      - '*'
      excludeNamespaces:
      - secure-ns
      signers:
      - signer-b
    - scope: Cluster
      signers:
      - signer-a
      - signer-b
    signers: ...
```

### Configure Verification Key
`secret` name must be specified for verifying signer subject configuration. This secret is also needed to be set in `keyConfig` in IShield CR. You can also specify public key filename (e.g. "pubring-a.gpg", "pubring-b.gpg") which contains exported public verification key. 

Here is the example to define multiple verification keys and multiple signers.

```yaml
spec:
  signerConfig:
    policies:
    - namespaces:
      - ns-a
      signers:
      - signer-a
    - namespaces:
      - 'ns-b'
      signers:
      - signer-b
    signers:
    - name: signer-a
      keyConfig: sample-verification-key-a
      subjects:
        email: signer-a@enterprise.com
    - name: signer-b
      keyConfig: sample-verification-key-b
      subjects:
        email: signer-b@enterprise.com
  keyConfig:
  - name: sample-verification-key-a
    secretName: keyring-secret-a
    fileName: pubring-a.gpg
  - name: sample-verification-key-b
    secretName: keyring-secret-b
    fileName: pubring-b.gpg
```


### Define Signer for cluster-scope resources
You can define a signer for cluster-scope resources similarily. Signer `signer-a` and `signer-b` can sign cluster-scope resources in the example below.

```yaml
spec:
  signerConfig:
    policies:
    - scope: Cluster
      signers:
      - signer-a
      - signer-b
```

### Break Glass
When you need to disable blocking by signature verification in a certain namespace, you can enable break glass mode, which means the request to the namespace without valid signature is allowed during the break glass on. For example, break glass on `secure-ns` namespace can be set on by

```yaml
spec:
  signerConfig:
    breakGlass:
      - namespaces:
        - secure-ns
```
Break glass on cluster-scope resources can be set on by
```yaml
spec:
  signerConfig:
    breakGlass:
      - scope: Cluster
```

During break glass mode on, the request without signature will be allowed even if protected by RSP, and the label `integrityshield.io/resourceIntegrity: unverified` will be attached to the resource.


### Example of Signer Configuration

```yaml
spec:
  signerConfig:
    policies:
    - namespaces:
      - secure-ns
      signers:
      - signer-a
    - namespaces:
      - '*'
      excludeNamespaces:
      - secure-ns
      signers:
      - signer-b
    - scope: Cluster
      signers:
      - signer-a
      - signer-b
    signers:
    - name: signer-a
      keyConfig: sample-signer-keyconfig-a
      subjects:
      - email: secure-ns-signer@enterprise.com
    - name: signer-b
      keyConfig: sample-signer-keyconfig-b
      subjects:
      - email: default-signer@enterprise.com
  keyConfig:
  - name: sample-signer-keyconfig-a
    secretName: keyring-secret-a
  - name: sample-signer-keyconfig-b
    secretName: keyring-secret-b  
```

