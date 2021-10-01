NAME=localhost:5000/k8s-manifest-sigstore-integrity-shield
VERSION=0.1.0

CERT_DIR ?= cert/
SERVICE_NAME ?= integrity-shield-api
K8S_MANIFEST_SIGSTORE_NS ?= k8s-manifest-sigstore
TMP_CERT_CONFIG_PATH ?= /tmp/api-crt.conf

.PHONY: build deploy undeploy

build:
	@echo building binary
	go mod tidy
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/ishield-api ./
	@echo building image
	docker build -t $(NAME):$(VERSION) .
	docker push $(NAME):$(VERSION)

deploy:
	kustomize build ./deploy | kubectl apply -n k8s-manifest-sigstore -f -

undeploy:
	kustomize build ./deploy | kubectl delete -n k8s-manifest-sigstore -f -
