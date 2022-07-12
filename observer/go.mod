module github.com/stolostron/integrity-shield/observer

go 1.16

require (
	github.com/open-policy-agent/gatekeeper v0.0.0-20220630222635-ff9f2cd29731
	github.com/sigstore/cosign v1.9.1-0.20220615165628-e4bc4a95743b
	github.com/sigstore/k8s-manifest-sigstore v0.3.1-0.20220620025919-87bf46f2b487
	github.com/sirupsen/logrus v1.8.1
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
	k8s.io/kubectl => k8s.io/kubectl v0.25.0-alpha.2
)
