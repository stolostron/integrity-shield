module github.com/stolostron/integrity-shield/integrity-shield-operator

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/go-logr/logr v1.2.3
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.19.0
	github.com/open-policy-agent/frameworks/constraint v0.0.0-20220627162905-95c012350402
	github.com/openshift/api v3.9.0+incompatible
	github.com/stolostron/integrity-shield/webhook/admission-controller v0.0.0-00010101000000-000000000000
	k8s.io/api v0.25.0-alpha.2
	k8s.io/apiextensions-apiserver v0.24.2
	k8s.io/apimachinery v0.25.0-alpha.2
	k8s.io/client-go v0.25.0-alpha.2
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.12.2
)

replace (
	github.com/stolostron/integrity-shield/integrity-shield-operator => ./
	github.com/stolostron/integrity-shield/shield => ../shield
	github.com/stolostron/integrity-shield/webhook/admission-controller => ../webhook/admission-controller
)

replace (
	github.com/open-policy-agent/gatekeeper => github.com/open-policy-agent/gatekeeper v0.0.0-20220630222635-ff9f2cd29731
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc => go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.20.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp => go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.20.0
	go.opentelemetry.io/otel => go.opentelemetry.io/otel v0.20.0
	go.opentelemetry.io/otel/metric => go.opentelemetry.io/otel/metric v0.20.0
	go.opentelemetry.io/otel/sdk => go.opentelemetry.io/otel/sdk v0.20.0
	go.opentelemetry.io/otel/trace => go.opentelemetry.io/otel/trace v0.20.0
	go.opentelemetry.io/proto/otlp => go.opentelemetry.io/proto/otlp v0.7.0
)
