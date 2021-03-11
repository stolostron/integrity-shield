# Configuration for RedHat OpenShift on IBM Cloud (ROKS)

## Set `roks` in Operator CR Options 
Integrity Shield is verified on ROKS environment as well as on other Kubernetes/OpenShift environment.

When you deploy Integrity Shield on ROKS, it is necessary to set just 1 parameter on CR so that you could avoid an issue related with OCP console login.

yaml
```
apiVersion: apis.integrityshield.io/v1alpha1
kind: IntegrityShield
metadata:
  name: integrity-shield-server
spec:
  shieldConfig:
    options: ["roks"] # this option should be set on ROKS
    ... 
```

By specifying this option, Integrity Shield operator will set concrete resources in a MutatingWebhookConfiguration, instead of "*". 

Otherwise, "*" for the cluster resource rule in webhook config causes the OCP console issue only on ROKS.


