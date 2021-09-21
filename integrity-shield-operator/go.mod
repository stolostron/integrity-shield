module github.com/IBM/integrity-enforcer/integrity-shield-operator

replace github.com/IBM/integrity-enforcer/integrity-verifier-operator => ../integrity-verifier-operator

go 1.13

require (
	cloud.google.com/go v0.70.0 // indirect
	github.com/IBM/integrity-enforcer/shield v0.0.0-20201001024601-320551d946dc
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32
	github.com/go-logr/logr v0.4.0
	github.com/google/go-cmp v0.5.5
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/openshift/api v3.9.0+incompatible
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	k8s.io/api v0.21.4
	k8s.io/apiextensions-apiserver v0.21.4
	k8s.io/apimachinery v0.21.4
	k8s.io/client-go v0.21.4
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.9.0
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.4-0.20200207053602-7439e774c9e9+incompatible
	github.com/IBM/integrity-enforcer/integrity-shield-operator => ./
	github.com/IBM/integrity-enforcer/shield => ../shield
	k8s.io/api => k8s.io/api v0.21.4
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.21.4
	k8s.io/apimachinery => k8s.io/apimachinery v0.21.4
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.21.4
	k8s.io/client-go => k8s.io/client-go v0.21.4
	k8s.io/kubectl => k8s.io/kubectl v0.21.4
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.9.0
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm

replace github.com/openshift/api => github.com/openshift/api v0.0.0-20190924102528-32369d4db2ad // Required until https://github.com/operator-framework/operator-lifecycle-manager/pull/1241 is resolved
