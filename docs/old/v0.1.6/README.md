# Integrity Shield

## Integrity Shield (IShield)
Integrity Shield is a tool for built-in preventive integrity control for regulated cloud workloads. It includes signature based configuration drift prevention based on [Admission Webhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) on Kubernetes cluster.

Integrity Shield's capabilities are

- Allow to deploy authorized application pakcages only
- Allow to use signed deployment params only
- Zero-drift in resource configuration unless whitelisted
- Perform all integrity verification on cluster (admission controller, not in client side)
- Handle variations in application packaging and deployment (Helm /Operator /YAML / OLM Channel) with no modification in app installer

## Quick Start
See [Quick Start](README_QUICK.md)

