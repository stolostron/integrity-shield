# Integrity Shield

## Integrity Shield
Integrity Shield is a tool for built-in preventive integrity control for regulated cloud workloads. It provides signature-based assurance of integrity for Kubernetes resources at cluster side.  

Integrity Shield API works with [OPA/Gatekeeper](https://github.com/open-policy-agent/gatekeeper), verifies if the requests attached a signature, and blocks any unauthorized requests according to the constraint before actually persisting in etcd. Integrity Shield API uses [k8s-manifest-sigstore](https://github.com/sigstore/k8s-manifest-sigstore) internally to verify Kubernetes manifest.

Integrity Shield also has auditing capability: Integrity Shield Observer periodically verifies resources on cluster and reports the status of Kubernetes manifest integrity.

Integrity Shield's capabilities are

- Allow to deploy authorized Kubernetes manifests only
- Zero-drift in resource configuration unless whitelisted
- Perform all integrity verification on cluster (admission controller, not in client side)
- Handle variations in application packaging and deployment (Helm /Operator /YAML / OLM Channel) with no modification in app installer
- Continuous resource monitoring

## Quick Start
See [Quick Start](README_QUICK.md)

