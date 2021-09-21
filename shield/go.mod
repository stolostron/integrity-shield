module github.com/IBM/integrity-enforcer/shield

replace github.com/IBM/integrity-enforcer/verifier => ../verifier

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm

go 1.13

require (
	github.com/ghodss/yaml v1.0.0
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a
	github.com/oliveagle/jsonpath v0.0.0-20180606110733-2e52cf6e6852
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/openshift/api v3.9.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/r3labs/diff v0.0.0-20191120142937-b4ed99a31f5a
	github.com/sirupsen/logrus v1.7.0
	github.com/tidwall/gjson v1.6.7
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	gopkg.in/yaml.v2 v2.4.0
	helm.sh/helm/v3 v3.0.2
	k8s.io/api v0.21.4
	k8s.io/apiextensions-apiserver v0.21.4
	k8s.io/apimachinery v0.21.4
	k8s.io/client-go v0.21.4
	k8s.io/kube-openapi v0.0.0-20210305001622-591a79e4bda7
	k8s.io/kubectl v0.21.4
	sigs.k8s.io/controller-runtime v0.9.0
)

replace (
	github.com/IBM/integrity-enforcer/shield => ./
	k8s.io/api => k8s.io/api v0.21.4
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.21.4
	k8s.io/apimachinery => k8s.io/apimachinery v0.21.4
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.21.4
	k8s.io/client-go => k8s.io/client-go v0.21.4
	k8s.io/code-generator => k8s.io/code-generator v0.21.4
	k8s.io/kubectl => k8s.io/kubectl v0.21.4
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.9.0
)
