module github.com/open-cluster-management/integrity-shield/logging

go 1.16

require (
	github.com/hpcloud/tail v1.0.0
	github.com/jasonlvhit/gocron v0.0.1
	github.com/sigstore/k8s-manifest-sigstore v0.1.0
	github.com/sirupsen/logrus v1.8.1
	k8s.io/apimachinery v0.22.3
	k8s.io/client-go v0.22.3
)

replace github.com/open-cluster-management/integrity-shield/logging => ./
