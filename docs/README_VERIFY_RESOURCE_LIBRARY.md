# VerifyResource
VerifyResource is a library which checks if admission request is valid based on signature and verification rule.

# How to use VerifyResource
Here is a [sample code](./example/verify-resource.go) to call VerifyResource.  
VerifyResource receives an admission request, a configuration (ManifestVerifyConfig), and a verification rule (ManifestVerifyRule). 
If you use default configuration, it can be `nil`. 

VerifyResource uses DryRun function internally. Therefore, creation permission to the DryRun namespace is required.
You can set DryRun namespace in ManifestVerifyConfig.

You can try the sample code with the following command.
```
cd docs/example
go run verify-resource.go

[VerifyResource Result] allow: true, reaseon: Singed by a valid signer: signer@enterprise.com
```

The following snippets are examples of ManifestVerifyConfig and ManifestVerifyRule.

1. ManifestVerifyRule
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

2. ManifestVerifyConfig

Please check [here](../shield/resource/manifest-verify-config.yaml).
