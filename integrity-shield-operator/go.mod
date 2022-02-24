module github.com/stolostron/integrity-shield/integrity-shield-operator

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/go-logr/logr v1.2.2
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.17.0
	github.com/open-policy-agent/frameworks/constraint v0.0.0-20210714212123-82a32eecb70d
	github.com/openshift/api v3.9.0+incompatible
	github.com/stolostron/integrity-shield/webhook/admission-controller v0.0.0-00010101000000-000000000000
	k8s.io/api v0.23.0
	k8s.io/apiextensions-apiserver v0.23.0-alpha.4
	k8s.io/apimachinery v0.23.0
	k8s.io/client-go v0.23.0
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.11.0-beta.0.0.20211115163949-4d10a0615b11
)

replace (
	github.com/stolostron/integrity-shield/integrity-shield-operator => ./
	github.com/stolostron/integrity-shield/shield => ../shield
	github.com/stolostron/integrity-shield/webhook/admission-controller => ../webhook/admission-controller
)
