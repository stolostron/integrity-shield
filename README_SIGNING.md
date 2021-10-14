# How to Sign Resources

## Signing Types

Integrity Shield supports three types of signing and verification.
- `pgp`: use [gpg key](https://www.gnupg.org/index.html) for signing. certificate is not used.
- `x509`: use x509 signing key and certificate. CA certificate is necessary for verification.
- `sigstore`: use [cosign key](https://github.com/sigstore/cosign) for signing with kubectl subcommand plugin in [k8s-manifest-sigstore](https://github.com/sigstore/k8s-manifest-sigstore) project.

## PGP

To sign a YAML manifest with gpg key, you need to specify signer email in your gpg signing key.

If you do not have any gpg key or you want to use a new key, generate a new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/)

You can run `scripts/gpg-annotation-sign.sh` script to generate signature annotations in YAML file which appends a signature for a Yaml file as annotations. For example,

```
$ ./scripts/gpg-annotation-sign.sh sample-signer@example.com sample-configmap.yaml
```

Note:  `gpg-annotation-sign.sh` will append the signature annotation to the input YAML file, please back up the original file if necessary.

You can verify a signed YAML manfiest file by the following script. It will show a message like this in case of success.

```
$ ./scripts/gpg-annotation-verify.sh sample-configmap.yaml path/to/public-keyring-file

Signature is successfully verified.
Verification: Success
```


## x509

To sign a YAML manifest with x509 signing key, you can run `scripts/gpg-annotation-sign.sh` script with x509 key and certificate.

```
$ ./scripts/x509-annotation-sign.sh path/to/key-file path/to/certificate-file sample-configmap.yaml
```

Note:  `x509-annotation-sign.sh` will append the signature annotation to the input YAML file, please back up the original file if necessary.

You can verify a signed YAML manfiest file by the following script. It will show a message like this in case of success.

```
$ ./scripts/x509-annotation-verify.sh sample-configmap.yaml path/to/CA-certificate-file

Signature is successfully verified.
Verification: Success
```

## Sigstore

To sign a YAML manifest with sigstore YAML manfiest signing, you can use `kubectl sigstore` command, which is provided by [sigstore/k8s-manifest-sigstore](https://github.com/sigstore/k8s-manifest-sigstore) project.

The actual signing command using kubectl sigstore is like this.

```
$ kubectl sigstore sign -f sample-configmap.yaml -k cosign.key
```

Verification command is something like this.

```
$ kubectl sigstore verify -f sample-configmap.yaml.signed -k cosign.pub
INFO[0000] verifed: true
```

About a detail description of this command, you can refer to [k8s-manifest-sigstore document](https://github.com/sigstore/k8s-manifest-sigstore/blob/main/docs/LATEST_RELEASE.md#whats-new-in-v010).

