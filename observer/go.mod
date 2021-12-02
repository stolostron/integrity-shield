module github.com/open-cluster-management/integrity-shield/observer

go 1.16

require (
	github.com/open-cluster-management/integrity-shield/reporter v0.0.0-00010101000000-000000000000
	github.com/open-cluster-management/integrity-shield/shield v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v1.3.1
	github.com/sigstore/k8s-manifest-sigstore v0.1.1-0.20211130202059-04091c44de91
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.23.0-alpha.4
	k8s.io/apimachinery v0.23.0-alpha.4
	k8s.io/client-go v0.23.0-alpha.4
)

require github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect

replace (
	github.com/open-cluster-management/integrity-shield/observer => ./
	github.com/open-cluster-management/integrity-shield/reporter => ../reporter
	github.com/open-cluster-management/integrity-shield/shield => ../shield
	github.com/open-cluster-management/integrity-shield/webhook/admission-controller => ../webhook/admission-controller
)
