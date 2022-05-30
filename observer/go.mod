module github.com/stolostron/integrity-shield/observer

go 1.16

require (
	github.com/open-policy-agent/gatekeeper v0.0.0-20210824170141-dd97b8a7e966
	github.com/sigstore/cosign v1.8.0
	github.com/sigstore/k8s-manifest-sigstore v0.2.1-0.20220526225831-5fdcfc72af99
	github.com/sirupsen/logrus v1.8.1
	github.com/stolostron/integrity-shield/reporter v0.0.0-00010101000000-000000000000
	github.com/stolostron/integrity-shield/shield v0.0.0-00010101000000-000000000000
	k8s.io/api v0.23.5
	k8s.io/apimachinery v0.23.5
	k8s.io/client-go v0.23.5
)

replace (
	github.com/stolostron/integrity-shield/observer => ./
	github.com/stolostron/integrity-shield/reporter => ../reporter
	github.com/stolostron/integrity-shield/shield => ../shield
	github.com/stolostron/integrity-shield/webhook/admission-controller => ../webhook/admission-controller
)
