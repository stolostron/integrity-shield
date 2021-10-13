## Disble Integrity Shield protection in an ACM managed cluster(s)

The document describe how to disable Integrity Shield (IShield) protection in an ACM managed cluster.

## Prerequisites
- An [ACM]((https://www.redhat.com/en/technologies/management/advanced-cluster-management)) hub cluster with one or more managed cluster attached to it and cluster admin access to the cluster to use `oc` or `kubectl` command.
- Integrity Shield protection is already enabled in an ACM managed cluster(s). Confirm the status (i.e. Compliance) of `policy-integrity-shield` in the ACM hub cluster. You can find `policy-integrity-shield` in the ACM Multicloud webconsole (Governace and Risk). 
- Disabling steps requires a host where we run the scripts.  Below steps are tested on Mac OS and Ubuntu hosts. 
- Disabling Integrity Shield protection and signing ACM polices involve retriving and commiting sources from GitHub repository. Make sure to install [git](https://github.com/git-guides/install-git) on the host. 

## Steps for disabling Integrity Shield protection in an ACM managed cluster(s)

You will use `policy-integrity-shield` to disable Integrity Shield protection in an ACM managed cluster(s) as described below.

 1. Go to the source of your cloned `policy-collection` GitHub repository in the host.  
   Find `policy-integrity-shield.yaml` in the directory `policy-collection/community/CM-Configuration-Management/` of the cloned GitHub repository.

 2. Configure `policy-integrity-shield.yaml` as below.  

    Change the `complianceType` configuration for `integrity-cr-policy` from `musthave` to `mustnothave` in `policy-integrity-shield.yaml`.

    The following example shows the `complianceType` configuration for `integrity-cr-policy` changed from `musthave` to `mustnothave`.

    ```
        - objectDefinition:
          apiVersion: policy.open-cluster-management.io/v1
          kind: ConfigurationPolicy
          metadata:
            name: policy-integrity-shield-cr
          spec:
            remediationAction: enforce 
            severity: high
            object-templates:
            - complianceType: mustnothave <<CHANGED FROM musthave>>
              objectDefinition:
                apiVersion: apis.integrityshield.io/v1alpha1
                kind: IntegrityShield
                metadata:
                  name: integrity-shield-server
                spec:
                  logger:
                    image: quay.io/open-cluster-management/integrity-shield-logging:0.3.0
                  server:
                    image: quay.io/open-cluster-management/integrity-shield-server:0.3.0
      ```
3.  Create signature annotation in `policy-integrity-shield.yaml` as below.

    Use the utility script [gpg-annotation-sign.sh](https://github.com/open-cluster-management/integrity-shield/blob/master/scripts/gpg-annotation-sign.sh) for signing updated `policy-integrity-shield` to be deployed to an ACM managed cluster.

      The following example shows how to use the utility script `gpg-annotation-sign.sh` to append signature annotations to `policy-integrity-shield.yaml`, with the following parameters:
      - `signer@enterprise.com` - The default `signer` email, or change it to your own `signer` email.
      - `CM-Configuration-Management/policy-integrity-shield.yaml` - the relative path of the updated policy file `policy-integrity-shield.yaml`

      ```
      $ cd policy-collection
      $ curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-shield/master/scripts/gpg-annotation-sign.sh | bash -s \
                    signer@enterprise.com \
                    community/CM-Configuration-Management/policy-integrity-shield.yaml
      ```

 4.  Commit the signed `policy-integrity-shield.yaml` file to the forked `policy-collection` GitHub repository.
 
      The ACM hub cluster will sync the updated `policy-integrity-shield` from GitHub repository to the ACM managed cluster(s). This will trigger disabling Integrity Shield protection in an ACM managed cluster(s). 

      Confirm the status (i.e. Compliance) of `policy-integrity-shield` in the ACM hub cluster. You can find `policy-integrity-shield` in the ACM Multicloud webconsole (Governace and Risk). Compliance status of `policy-integrity-shield` means that `policy-integrity-shield` is updated in an ACM managed cluster(s). 

      Once you disable Integrity Shield protection,  you can edit any ACM policies in an ACM managed cluster(s) without signature.

## Steps for removing Integrity Shield operator from an ACM managed cluster(s)

- Step 1: Disable Integrity Shield protection in an ACM managed cluster(s) as described above, before removing Integrity Shield operator from an ACM managed cluster(s).
- Step 2: Follow the following steps to remove Integrity Shield operator from an ACM managed cluster(s).

1. Configure `policy-integrity-shield.yaml` as below.      
    
     Find all instances of `musthave` in `policy-integrity-shield.yaml` and change it to `mustnothave`

    The following example shows an instance of change from `musthave` to `mustnothave`.

    ```
    - objectDefinition:
      apiVersion: policy.open-cluster-management.io/v1
      kind: ConfigurationPolicy
      metadata:
        name: policy-integrity-shield-namespace
      spec:
        remediationAction: enforce
        severity: High
        object-templates:
        - complianceType: mustnothave  <<CHANGED FROM musthave>>
          objectDefinition:
            kind: Namespace 
            apiVersion: v1
            metadata:
              name: integrity-shield-operator-system
    ```
2. Commit the update `policy-integrity-shield.yaml` file to the `policy-collection` GitHub repository.

    ACM hub cluster will sync the updated `policy-integrity-shield` from GitHub repository to the ACM managed cluster(s). This will trigger removing Integrity Shield operator from an ACM managed cluster(s).  

    Note that this will also remove secret resource with verification key setup in [doc](README_SETUP_KEY_RING_ACM_ENV.md). If you would need to reenable Integrity Shield Protection to an ACM managed cluster, follow the [doc](README_SETUP_KEY_RING_ACM_ENV.md) to setup the verification key in an ACM managed cluster(s)

    Confirm the status (i.e. Compliance) of `policy-integrity-shield` in the ACM hub cluster. You can find `policy-integrity-shield` in the ACM Multicloud webconsole (Governace and Risk). Compliance status of `policy-integrity-shield` means that `policy-integrity-shield` is updated in an ACM managed cluster(s) and Integrity Shield operator is removed from an ACM managed cluster(s).

## Steps for removing `policy-integrity-shield` from an ACM managed cluster(s)    

- Step 1: Disable Integrity Shield protection in an ACM managed cluster(s)

- Step 2: Remove Integrity Shield operator from an ACM managed cluster(s)

- Step 3: Follow the following steps to remove `policy-integrity-shield` from an ACM managed cluster(s) after disabling Integrity Protection and removing Integrity Shield operator from an ACM managed cluster(s)

1. Configure `policy-integrity-shield.yaml` as below. 

    Change `placement rule` in `policy-integrity-shield.yaml` as shown below.

      ```
         apiVersion: apps.open-cluster-management.io/v1
         kind: PlacementRule
         metadata:
           name: placement-policy-integrity-shield
         spec:
           clusterConditions:
           - status: "True"
             type: ManagedClusterConditionAvailable
           clusterSelector:
             matchExpressions:
             - {key: environment, operator: In, values:   ["-"]}
      ``` 

2. Commit the changes in `policy-integrity-shield.yaml` file to the  `policy-collection` GitHub repository.
  
    ACM hub cluster will sync the updated `policy-integrity-shield` from GitHub repository to the ACM managed cluster(s). This will trigger removing `policy-integrity-shield` from the ACM managed cluster(s). 
        
     
