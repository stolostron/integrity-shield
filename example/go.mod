module github.com/stolostron/integrity-shield/docs/example

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/stolostron/integrity-shield/shield v0.0.0-00010101000000-000000000000
	k8s.io/api v0.23.4
)

replace github.com/stolostron/integrity-shield/shield => ../../shield
