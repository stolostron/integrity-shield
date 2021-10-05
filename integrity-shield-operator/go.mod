module github.com/IBM/integrity-enforcer/integrity-shield-operator

go 1.16

require (
	github.com/IBM/integrity-enforcer/webhook/admission-controller v0.0.0-00010101000000-000000000000
	github.com/ghodss/yaml v1.0.0
	github.com/go-logr/logr v0.4.0
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.15.0
	github.com/open-policy-agent/frameworks/constraint v0.0.0-20210714212123-82a32eecb70d
	github.com/openshift/api v3.9.0+incompatible
	k8s.io/api v0.22.1
	k8s.io/apiextensions-apiserver v0.22.1
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v0.22.1
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.9.0
)

replace (
	github.com/IBM/integrity-enforcer/integrity-shield-operator => ./
	github.com/IBM/integrity-enforcer/shield => ../shield
	github.com/IBM/integrity-enforcer/webhook/admission-controller => ../webhook/admission-controller
)
