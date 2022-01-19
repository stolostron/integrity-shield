module github.com/open-cluster-management/integrity-shield/observer

go 1.16

require (
	github.com/open-cluster-management/integrity-shield/reporter v0.0.0-00010101000000-000000000000
	github.com/open-cluster-management/integrity-shield/shield v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v1.4.1
	github.com/sigstore/k8s-manifest-sigstore v0.1.1-0.20220118010220-78aa67750956
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.23.0
	k8s.io/apimachinery v0.23.0
	k8s.io/client-go v0.23.0
)

replace (
	github.com/open-cluster-management/integrity-shield/observer => ./
	github.com/open-cluster-management/integrity-shield/reporter => ../reporter
	github.com/open-cluster-management/integrity-shield/shield => ../shield
	github.com/open-cluster-management/integrity-shield/webhook/admission-controller => ../webhook/admission-controller
)
