# How to deploy a verification key to an ACM managed cluster.

## Prerequisites
​
The following prerequisites must be satisfied to deploy Integrity Shield on an ACM managed cluster via [ACM policies](https://github.com/stolostron/policy-collection).
- An [ACM]((https://www.redhat.com/en/technologies/management/advanced-cluster-management)) hub cluster with one or more managed cluster attached to it and cluster admin access to the cluster to use `oc` or `kubectl` command
- The namespace where verification key would be deployed, is already created in Step 1 in [doc](README_ENABLE_ISHIELD_PROTECTION_ACM_ENV.md)

## Setup verification key in an ACM managed cluster(s)
A secret resource (default name `keyring-secret`) which contains a public key should be setup in an ACM managed cluster(s) for enabling signature verification by Integrity Shield. 

Setting up a verification key on an ACM managed cluster requires the following steps:
 - Step 1 Create signing and verification key pairs
 - Step 2 Deploy verification key to an ACM hub cluster so that it can probagate to a managed cluster(s).


### Step 1 Create signing and verification key pairs

To see how to create a verification key,  refer to [doc](../README_VERIFICATION_KEY_SETUP.md)


### Step 2 Deploy verification key to an ACM hub cluster so that it can probagate to a managed cluster(s).

First connect to an ACM hub cluster and execute the [acm-verification-key-setup.sh](https://raw.githubusercontent.com/stolostron/integrity-shield/master/scripts/ACM/acm-verification-key-setup.sh) script to setup a verification key on an ACM managed cluster(s) connected to the ACM hub cluster with the following parameters:

- `integrity-shield-operator-system` - The namespace where verification key would be created in the ACM hub cluster. This should be the namespace created in Step 1 in [doc](README_ENABLE_ISHIELD_PROTECTION_ACM_ENV.md)
- `keyring-secret` - The name of secret resource which would include the verification key. The name should match with signer in `policy-integrity-shield.yaml` (see Step 3.b in [doc](README_ENABLE_ISHIELD_PROTECTION_ACM_ENV.md))
- `/tmp/pubring.gpg` - The file path of the verification key exported as described in [doc](../README_VERIFICATION_KEY_SETUP.md)
- `environment:dev` - The placement rule flags which are the labels/tags that idetifies a managed cluster(s). Use the flags to setup ACM placement rule that selects the managed clusters in which the verification key needs to be setup. (e.g. environment:dev).  See [doc](https://github.com/stolostron/policy-collection)

```
curl -s  https://raw.githubusercontent.com/stolostron/integrity-shield/master/scripts/ACM/acm-verification-key-setup.sh | bash -s \
          --namespace integrity-shield-operator-system  \
          --secret keyring-secret  \
          --path /tmp/pubring.gpg \
          --label environment=dev  |  oc apply -f -
```


## Remove verification key from an ACM hub cluster and an ACM  managed cluster(s)

First connect to a ACM hub cluster where a verification key is already setup and execute the following script to delete the key from hub the cluster as well as a managed cluster(s) with the following parameters:

- `integrity-shield-operator-system` - The namespace where verification key would be created in the ACM hub cluster. This should be the namespace created in Step 1 in [doc](README_ENABLE_ISHIELD_PROTECTION_ACM_ENV.md)
- `keyring-secret` - The name of secret resource which would include the verification key
- `/tmp/pubring.gpg` - The file path of the verification key exported as described in [doc](../README_VERIFICATION_KEY_SETUP.md)
- `environment:dev` - The placement rule flags which are the labels/tags that idetifies a managed cluster(s). Use the flags to setup ACM placement rule that selects the managed clusters in which the verification key needs to be setup. (e.g. environment:dev).  See [doc](https://github.com/stolostron/policy-collection)

```
curl -s  https://raw.githubusercontent.com/stolostron/integrity-shield/master/scripts/ACM/acm-verification-key-setup.sh | bash -s - \
          --namespace integrity-shield-operator-system  \
          --secret keyring-secret  \
          --path /tmp/pubring.gpg \
          --label environment=dev  |  oc delete -f -
```

## Changing the verification key

If you need to change the verification key that can be accomplished by completing the "Setup verification key" procedure which would apply the new verification key to a secret named `keyring-secret`.  After following this procedure only the new keys can be used for signing and verification.

