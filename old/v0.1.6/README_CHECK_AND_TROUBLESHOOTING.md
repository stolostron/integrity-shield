# Check and Troubleshooting

## How to check Integrity Shield working

### Check Installation

To check if Integrity Shield is correctly deployed, you can check Pod status and webhook existence like the following.

If `integrity-shield-server` Pod is Running and a WebhookConfiguration is there, Integrity Shield is installed and working.


```
$ oc get pod -n integrity-shield-operator-system
NAME                                                           READY   STATUS    RESTARTS   AGE
integrity-shield-operator-controller-manager-7df9cfffd-tzq2f   1/1     Running   0          23m
integrity-shield-server-8469845dd-98bld                        2/2     Running   0          22m

$ oc get mutatingwebhookconfiguration
NAME                     WEBHOOKS   AGE
ishield-webhook-config   1          22m
```

### Check Integrity Shield Events

Integrity Shield reports all events that were denied by Integrity Shield itself. 

You can see all denied requests as Kubernetes Event like below.

```
$ oc get event -n secure-ns --field-selector type=IntegrityShield

LAST SEEN   TYPE              REASON         OBJECT                MESSAGE
27s         IntegrityShield   no-signature   configmap/test-cm   [IntegrityShieldEvent] Result: deny, Reason: "Signature verification is required for this request, but no signature is found. Please attach a valid signature to the annotation or by a ResourceSignature.", Request: {"kind":"ConfigMap","name":"test-cm","namespace":"secure-ns","operation":"CREATE","request.uid":"cfea7d34-0bf0-4e6a-9b59-e53290e02e67","scope":"Namespaced","userName":"kubernetes-admin"}
```

This is an example of ConfigMap request, so the event is reported in the same namespace as ConfigMap namespace.

If a request of Cluster-scoped resource such as ClusterRole is denied by Integrity Shield, the event will be created in the same namespace as Integrity Shield.

To check all denied events in your cluster, simply you can run the command below.

```
$ oc get event --all-namespaces --field-selector type=IntegrityShield
```

If you want to check not only denied events but also allowed events, they are logged in container log. Please see the next section.


### Check RSP status

Resource Signing Profile (RSP) defines what resource should be protected by Integrity Shield, so RSP status shows corresponding denied events if exist.

You can check RSP status like the following.

```
$ oc describe rsp -n secure-ns sample-rsp

...

Status:
  Deny Count:  1
  Deny Summary:
    Count:               1
    Group Version Kind:  /v1, Kind=ConfigMap
  Latest Denied Events:
    Request:
      API Version:  v1
      Kind:         ConfigMap
      Name:         sample-cm
      Namespace:    secure-ns
      Operation:    CREATE
      User Name:    kubernetes-admin
    Result:
      Message:    Signature verification is required for this request, but no signature is found. Please attach a valid signature to the annotation or by a ResourceSignature.
      Timestamp:  2021-01-13 07:34:21

```

### Check Integrity Verified Resources

When you want to check what resources are verified with their signatures, you can use a script named [`list_signed_resources.sh `](../scripts/list_signed_resources.sh).

This script shows you a list of resources that are verified by Integrity Shield, and you can use a short name for a kind argument like below.

```
$ ./scripts/list_signed_resources.sh deployment
--- Deployment ---
NAMESPACE  NAME               SIGNER                 LAST_VERIFIED         RSIG_UID
secure-ns  sample-deployment  signer@enterprise.com  2021-01-20T07:28:09Z  2de4ea9e-7bfb-45fd-a730-ab866cfd4332

$ ./scripts/list_signed_resources.sh cm
--- ConfigMap ---
NAMESPACE  NAME         SIGNER                 LAST_VERIFIED         RSIG_UID
secure-ns  sample-cm    signer@enterprise.com  2021-01-20T07:27:59Z  ac31dd59-6f73-4958-a21a-df337fbf5d07
secure-ns  sample-cm-2  signer@enterprise.com  2021-01-20T07:43:38Z  08dbcb7d-3055-4a84-8246-302510d9b76c
```

Also, you can specify `all` as kind argument, but please note that this queries `kubectl get` API for all valid resource kinds. The output will be like following.
```
$ ./scripts/list_signed_resources.sh all
--- ConfigMap ---
NAMESPACE  NAME         SIGNER                 LAST_VERIFIED         RSIG_UID
secure-ns  sample-cm    signer@enterprise.com  2021-01-20T07:27:59Z  ac31dd59-6f73-4958-a21a-df337fbf5d07
secure-ns  sample-cm-2  signer@enterprise.com  2021-01-20T07:43:38Z  08dbcb7d-3055-4a84-8246-302510d9b76c

--- Service ---
NAMESPACE  NAME          SIGNER                 LAST_VERIFIED         RSIG_UID
secure-ns  test-service  signer@enterprise.com  2021-01-20T07:27:20Z  null

--- Deployment ---
NAMESPACE  NAME               SIGNER                 LAST_VERIFIED         RSIG_UID
secure-ns  sample-deployment  signer@enterprise.com  2021-01-20T07:28:09Z  2de4ea9e-7bfb-45fd-a730-ab866cfd4332

--- ClusterRole ---
NAMESPACE  NAME            SIGNER                 LAST_VERIFIED         RSIG_UID
-          sample-sa-role  signer@enterprise.com  2021-01-20T07:48:41Z  aa63307a-a938-4efd-8d98-dd1f8b0442eb
```


## Troubleshooting

### Install issue

If only operator Pod (`integrity-shield-operator-controller-xxxx-xxxx` by default) is running and there is no `integrity-shield-server-xxxx-xxxx` Pod, please check operator container log.

If you see the log message like below, some required verification key secret are not ready. Once you deployed the secret there, installation will be started by operator.

```
$ oc get pod -n integrity-shield-operator-system
NAME                                                           READY   STATUS    RESTARTS   AGE
integrity-shield-operator-controller-manager-7df9cfffd-tzq2f   1/1     Running   0          2m


$ oc logs deployment.apps/integrity-shield-operator-controller-manager

...

2021-01-13T09:06:15.279Z        INFO    controllers.IntegrityShield     KeyRing secret "keyring-secret" does not exist. Skip reconciling.       {"Request.Namespace": "integrity-shield-operator-system", "Request.Name": "integrity-shield-server"}
2021-01-13T09:06:15.286Z        INFO    controllers.IntegrityShield     KeyRing secret "keyring-secret" does not exist. Skip reconciling.       {"Request.Namespace": "integrity-shield-operator-system", "Request.Name": "integrity-shield-server"}
2021-01-13T09:06:15.299Z        INFO    controllers.IntegrityShield     KeyRing secret "keyring-secret" does not exist. Skip reconciling.       {"Request.Namespace": "integrity-shield-operator-system", "Request.Name": "integrity-shield-server"}
```


### Uninstall issue

Integrity Shield protects Integirty Shield itself, so uninstalling it should be done by some correct steps.

Documents and some scripts in this repository provide automated ways to uninstall Integrity Shield, so basically you don't need to know the actual steps.

But sometimes you might face a issue around uninstall due to some reasons, and you might not be able to uninstall it.

In such a case, deleting `MutatingWebhookConfiguration` of IntegrityShield could solve the situation.

Here is example steps of manual uninstall for Integrity Shield.

```
$ oc delete mutatingwebhookconfiguration ishield-webhook-config
mutatingwebhookconfiguration.admissionregistration.k8s.io "ishield-webhook-config" deleted

$ oc delete integrityshield integrity-shield-server -n integrity-shield-operator-system
integrityshield.apis.integrityshield.io "integrity-shield-server" deleted

$ oc get pod -n integrity-shield-operator-system
NAME                                                           READY   STATUS    RESTARTS   AGE
integrity-shield-operator-controller-manager-7df9cfffd-tzq2f   1/1     Running   0          23m
```

After deleting IntegrityShield CR, the server Pod will be deleted (because CR is the owner).

Once you successfully deleted server Pod, no blocking functions are working anymore, so you can delete all other resources if you want.

### Unexpected Deny

If your request has been denied in spite of non-protected resource, please check RSPs in the cluster.

Basically, RSPs in a certain namespace can be used only for protection of resources in the namespace.

However, RSPs in Integrity Shield namespace (`integrity-shield-operator-system` by default) can be used as something like global configuration, so it can define any namespace rule.

To see all RSPs in your cluster, you can use a [list_rsp.sh ](../scripts/list_rsp.sh) (Use `jq` and `column` in the script)

```
$ ./scripts/list_rsp.sh
NAMESPACE                         NAME                    RULES                                                                                      TARGET_NAMESPACE
integrity-shield-operator-system  global-rsp              {"protectRules":[{"match":[{"kind":"Service"}]}]}                                          {"exclude":["kube-*"],"include":["*"]}
secure-ns                         sample-rsp              {"protectRules":[[{"match":[{"kind":"Pod"},{"kind":"ConfigMap"},{"kind":"Deployment"}]}]}  secure-ns
test-ns                           sample-clusterrole-rsp  {"protectRules":[[{"match":[{"kind":"ClusterRole"}]}]}                                     test-ns
```

Additionally, if you are using ResourceSignature instead of annotation signature, you can list all ResourceSignatures in your cluster by a script [list_rsig.sh ](../scripts/list_rsig.sh) . 

This might be useful to solve some issues caused by mis-configured ResourceSignature.

```
$ ./scripts/list_rsig.sh
NAMESPACE  NAME                               SIGNED_OBJECT                           SIGNED_TIME(UTC)
secure-ns  rsig-configmap-sample-cm           kind=ConfigMap,name=sample-cm           2021-01-13T10:52:38Z
test-ns    rsig-deployment-sample-deployment  kind=Deployment,name=sample-deployment  2021-01-13T10:53:27Z
```


### Unexpected Allow

If your request has been allowed unexpectedly, please check if Integrity Shield is correctly working in the cluster first.
You can check it following [this](#check-installtion) .

Also, mis-configured RSP might cause unexpected allow, so the script above ([list_rsp.sh](../scripts/list-rsp.sh)) might be useful to check RSP configurations.

If Integirty Shield and RSPs are correctly set up in the cluster, server container of integrity-shield-server Pod might log unexpected error, this should not be happened though.

In this case, reporting issue with your log will be great help for us to improve Integrity Shield even more. We would really appreciate you if you could report any issue.

