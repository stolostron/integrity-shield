module github.com/open-cluster-management/integrity-shield/shield

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/jinzhu/copier v0.3.2
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v1.2.0
	github.com/sigstore/k8s-manifest-sigstore v0.1.0
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.22.1
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v0.22.1
	sigs.k8s.io/controller-runtime v0.9.0
)

replace github.com/open-cluster-management/integrity-shield/shield => ./
