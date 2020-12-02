module github.com/IBM/integrity-enforcer/integrity-verifier-operator

replace github.com/IBM/integrity-enforcer/integrity-verifier-operator => ../integrity-verifier-operator

go 1.13

require (
	cloud.google.com/go v0.70.0 // indirect
	github.com/IBM/integrity-enforcer/verifier v0.0.0-20201001024601-320551d946dc
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32
	github.com/go-logr/logr v0.2.1
	github.com/go-logr/zapr v0.2.0 // indirect
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.3
	github.com/openshift/api v0.0.0-20200205133042-34f0ec8dab87
	github.com/prometheus/client_golang v1.8.0 // indirect
	github.com/sirupsen/logrus v1.7.0 // indirect
	go.uber.org/zap v1.16.0 // indirect
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	k8s.io/api v0.19.3
	k8s.io/apiextensions-apiserver v0.19.3
	k8s.io/apimachinery v0.19.3
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.6.3
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.4-0.20200207053602-7439e774c9e9+incompatible
	github.com/IBM/integrity-enforcer/verifier => ../verifier
	k8s.io/api => k8s.io/api v0.18.6
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.18.6
	k8s.io/apimachinery => k8s.io/apimachinery v0.18.6
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.18.6
	k8s.io/client-go => k8s.io/client-go v0.18.6
	k8s.io/kubectl => k8s.io/kubectl v0.18.6
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.6.2
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm

replace github.com/openshift/api => github.com/openshift/api v0.0.0-20190924102528-32369d4db2ad // Required until https://github.com/operator-framework/operator-lifecycle-manager/pull/1241 is resolved

replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
