module github.com/stolostron/integrity-shield/reporter

go 1.16

require (
	github.com/hpcloud/tail v1.0.0
	github.com/jasonlvhit/gocron v0.0.1
	github.com/sirupsen/logrus v1.9.0
	github.com/stolostron/integrity-shield/shield v0.0.0-00010101000000-000000000000
	k8s.io/apimachinery v0.25.0-alpha.2
	k8s.io/client-go v0.25.0-alpha.2
)

replace (
	github.com/stolostron/integrity-shield/reporter => ./
	github.com/stolostron/integrity-shield/shield => ../shield

)
