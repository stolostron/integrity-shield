# VerifyResource
VerifyResource is a library which checks if admission request is valid based on signature and verification rule.

# How to use VerifyResource
## Prerequisite
- kubectl command
- creation permission: VerifyResource uses DryRun function internally. Therefore, `creation permission` to the DryRun namespace is required.

## Example
Here is a [sample code](./example/verify-resource.go) to call VerifyResource.  

This example uses these files in the [example dir](./example).

- [verify-resource.go](./example/verify-resource.go) : example code
- [sample-cm.yaml](./example/sample-cm.yaml) : sample resource
- [sample-cm-w-sig.yaml](./example/sample-cm-w-sig.yaml) : sample resource signed by `signer@enterprise.com`
- [sample-adm-req-wo-sig.json](./example/sample-adm-req-wo-sig.json) : admission request of sample-cm without signature
- [sample-adm-req-w-sig.json](./example/sample-adm-req-w-sig.json) : admission request of sample-cm signed by `signer@enterprise.com`
- [sample-rule.yaml](./example/sample-rule.yaml) : sample ManifestVerifyRule


You can try the sample code with the following command.

VerifyResource receives an `admission request` and a `ManifestVerifyRule`, then returns the validation result.

1. Admission request without signature will not be accepted.
```
cd docs/example
go run verify-resource.go sample-adm-req-wo-sig.json sample-rule.yaml

[VerifyResource Result] allow: false, reaseon: failed to verify signature: failed to get signature: `cosign.sigstore.dev/message` is not found in the annotations
```
1. Admission request with signature will be accepted.
```
go run verify-resource.go sample-adm-req-w-sig.json sample-rule.yaml

[VerifyResource Result] allow: true, reaseon: Singed by a valid signer: signer@enterprise.com
```

The following snippet is a sample ManifestVerifyRule.

You can define rules to verify resource such as target object (namespace/kind/name etc.), public key, allow ServiceAccount, allow change patterns etc. 

ManifestVerifyRule
```yaml
objectSelector:
- name: sample-cm
ignoreFields:
- objects:
  - kind: ConfigMap
  fields:
  - data.comment
keyConfigs:
- key:
    name: keyring
    PEM: |-
      -----BEGIN PGP PUBLIC KEY BLOCK-----

      mQENBF+0ogoBCADiOMDUUXI/dnPjSj1GTJ5pNv6GTzxEEkFNSjzskTyGPwE+D14y
      iZ74BwIsa+n0hZHWfUeGP41oxMxBsTx+F7AHb4i/7SXg8K6Qg07xJgy1Q5fV7m7E
      liVZ9Xso5VqrEyTaa8ipC2DCvSYkWUD3fKR3W5dh18qqr6RCSkMltiIb2IG9DNQS...
      -----END PGP PUBLIC KEY BLOCK-----
```