module github.com/stolostron/integrity-shield/webhook/admission-controller

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/jinzhu/copier v0.3.2
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v1.10.1
	github.com/sigstore/k8s-manifest-sigstore v0.4.0
	github.com/sirupsen/logrus v1.9.0
	github.com/stolostron/integrity-shield/shield v0.0.0-00010101000000-000000000000
	k8s.io/api v0.25.0-alpha.2
	k8s.io/apimachinery v0.25.0-alpha.2
	k8s.io/client-go v0.25.0-alpha.2
	sigs.k8s.io/controller-runtime v0.12.3
)

replace (
	github.com/stolostron/integrity-shield/shield => ../../shield
	github.com/stolostron/integrity-shield/webhook/admission-controller => ./
	k8s.io/kubectl => k8s.io/kubectl v0.25.0-alpha.2
)
