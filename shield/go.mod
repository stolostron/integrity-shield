module github.com/open-cluster-management/integrity-shield/shield

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/jinzhu/copier v0.3.2
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v1.3.1
	github.com/sigstore/k8s-manifest-sigstore v0.1.1-0.20211130202059-04091c44de91
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.23.0-alpha.4
	k8s.io/apimachinery v0.23.0-alpha.4
	k8s.io/client-go v0.23.0-alpha.4
	sigs.k8s.io/controller-runtime v0.11.0-beta.0.0.20211115163949-4d10a0615b11
)

require k8s.io/utils v0.0.0-20211116205334-6203023598ed // indirect

replace github.com/open-cluster-management/integrity-shield/shield => ./

// replace (
// 	k8s.io/api v0.23.0-alpha.4 => k8s.io/api v0.22.3
// 	k8s.io/apimachinery v0.23.0-alpha.4 => k8s.io/apimachinery v0.22.3
// 	k8s.io/client-go v0.23.0-alpha.4 => k8s.io/client-go v0.22.3
// )
