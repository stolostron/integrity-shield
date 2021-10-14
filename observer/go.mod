module github.com/open-cluster-management/integrity-shield/observer

go 1.16

require (
	github.com/open-cluster-management/integrity-shield/shield v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v1.2.0
	github.com/sigstore/k8s-manifest-sigstore v0.1.0
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.22.1
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v0.22.1
)

replace (
	github.com/open-cluster-management/integrity-shield/observer => ./
	github.com/open-cluster-management/integrity-shield/shield => ../shield
	github.com/open-cluster-management/integrity-shield/webhook/admission-controller => ../webhook/admission-controller
)
