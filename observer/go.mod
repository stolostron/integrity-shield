module github.com/stolostron/integrity-shield/observer

go 1.16

require (
	github.com/open-policy-agent/gatekeeper v0.0.0-20220630222635-ff9f2cd29731
	github.com/sigstore/cosign v1.10.1
	github.com/sigstore/k8s-manifest-sigstore v0.3.1-0.20220810053329-14f7cab4fd52
	github.com/sirupsen/logrus v1.9.0
	github.com/stolostron/integrity-shield/reporter v0.0.0-00010101000000-000000000000
	github.com/stolostron/integrity-shield/shield v0.0.0-00010101000000-000000000000
	k8s.io/api v0.25.0-alpha.2
	k8s.io/apimachinery v0.25.0-alpha.2
	k8s.io/client-go v0.25.0-alpha.2
)

replace (
	github.com/stolostron/integrity-shield/observer => ./
	github.com/stolostron/integrity-shield/reporter => ../reporter
	github.com/stolostron/integrity-shield/shield => ../shield
	github.com/stolostron/integrity-shield/webhook/admission-controller => ../webhook/admission-controller
	k8s.io/kubectl => k8s.io/kubectl v0.25.0-alpha.2
)
