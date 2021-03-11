# Limitation

## Signature Protection Availability  


Integrity Shield provides signature protection to Kubernetes resources and some other artifacts, but there is a limitation in terms of availability.

Integrity Shield monitors Kubernetes resource request like create/update/delete as an admission controller, and an admission controller is connected to Kubernetes API server.

So, when the API server and some other fundamental components are not available, signature protection cannot be performed by Integrity Shield.

For example, when you are trying to upgrade the running cluster, its API server would become unavailable for a while.

During this, signature protection is also unavailable. And after all components get running, it will become available again.

