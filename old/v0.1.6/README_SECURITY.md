# Security in Integrity Shield

- Integrity Shield uses public key specified in Integrity Shield CR for signature verification. Public key only is deployed in cluster as Kubernetes secret, and no signing key is required on cluster.

- The following table includes the list of resources created by Integrity Shield as default (assuming the IShield is deployed on  `integrity-shield-operator-system` namespace.) No user has direct access to resources managed by IShield operator. All those resources are created/updated by IShield operator according to IShield CR. All pods are running in runAsNonRoot, no runAsUser, and run with `restricted` [SCC](https://docs.openshift.com/container-platform/4.6/authentication/managing-security-context-constraints.html). 


| kind | name | namespace | owned-by |
| ---- | ---- | ---- | ---- |
| Deployment | integrity-shield-operator-controller-manager | integrity-shield-operator-system | - |
| IntegrityShield | integrity-shield-server | integrity-shield-operator-system | - |
| ShieldConfig | ishield-config | integrity-shield-operator-system | IShield operator |
| SignPolicy | sign-policy | integrity-shield-operator-system | IShield operator |
| Secret | ishield-server-tls | integrity-shield-operator-system | IShield operator |
| ServiceAccount | ishield-sa | integrity-shield-operator-system | IShield operator |
| Role | ishield-cluster-role-sim | integrity-shield-operator-system | IShield operator |
| RoleBinding | ishield-cluster-role-binding-sim | integrity-shield-operator-system | IShield operator |
| Role | ishield-admin-role | integrity-shield-operator-system | IShield operator |
| RoleBinding | ishield-admin-rolebinding | integrity-shield-operator-system | IShield operator |
| PodSecurityPolicy | ishield-psp | integrity-shield-operator-system | IShield operator |
| Deployment | integrity-shield-server | integrity-shield-operator-system | IShield operator |
| ServiceAccount | integrity-shield-operator-manager | integrity-shield-operator-system | - |
| CustomResourceDefinition | integrityshields.apis.integrityshield.io | (cluster scope) | - |
| CustomResourceDefinition | shieldconfigs.apis.integrityshield.io | (cluster scope) | IShield operator |
| CustomResourceDefinition | signpolicies.apis.integrityshield.io | (cluster scope) | IShield operator |
| CustomResourceDefinition | resourcesignatures.apis.integrityshield.io | (cluster scope) | IShield operator |
| CustomResourceDefinition | resourcesigningprofiles.apis.integrityshield.io | (cluster scope) | IShield operator |
| CustomResourceDefinition | helmreleasemetadatas.apis.integrityshield.io | (cluster scope) | IShield operator |
| ClusterRole | ishield-cluster-role | (cluster scope) | IShield operator |
| ClusterRoleBinding | ishield-cluster-role-binding | (cluster scope) | IShield operator |
| ClusterRole | ishield-admin-clusterrole | (cluster scope) | IShield operator |
| ClusterRoleBinding | ishield-admin-clusterrolebinding | (cluster scope) | IShield operator |
| ClusterRole | integrity-shield-operator-manager-role | (cluster scope) | - |
| ClusterRoleBinding | integrity-shield-operator-manager-rolebinding | (cluster scope) | - |
| WebhookConfiguration | ishield-webhook-config | (cluster scope) | IShield operator |

- There are two ways to setup RSPs. RSP can be deployed by specifiying RSP in Integrity Shield CR. IShield operator creates RSP in IShield namespace (integrity-shield-operator-system). RSPs is applied to the namespaces specified in targetNamespace selector in the RSP. This RSP cannot be accessed directly, but managed by IShield operator. 
- User can define custom RSPs for each namespace to protect specific resources on the same namespace. **User needs to put proper protection to RSP (with RBAC or with RSP itself.)** The RSP in a namespace cannot be applicable to the resources on other namespace. 
- RSP can specify cluster scope resource for protection, but resource name of the protected resource must be specified explicitly.