module github.com/stolostron/integrity-shield/integrity-shield-operator

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/go-logr/logr v1.2.3
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.19.0
	github.com/open-policy-agent/frameworks/constraint v0.0.0-20220719222628-b0dbc52e8449
	github.com/openshift/api v3.9.0+incompatible
	github.com/stolostron/integrity-shield/webhook/admission-controller v0.0.0-00010101000000-000000000000
	k8s.io/api v0.25.0-alpha.2
	k8s.io/apiextensions-apiserver v0.24.2
	k8s.io/apimachinery v0.25.0-alpha.2
	k8s.io/client-go v0.25.0-alpha.2
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.12.3
)

replace (
	github.com/open-policy-agent/opa => github.com/open-policy-agent/opa v0.44.0
	github.com/stolostron/integrity-shield/integrity-shield-operator => ./
	github.com/stolostron/integrity-shield/shield => ../shield
	github.com/stolostron/integrity-shield/webhook/admission-controller => ../webhook/admission-controller
	k8s.io/kubectl => k8s.io/kubectl v0.25.0-alpha.2
)
