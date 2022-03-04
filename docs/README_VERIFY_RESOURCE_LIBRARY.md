# VerifyResource
VerifyResource is a library which checks if admission request is valid based on signature and verification rule.

# How to VerifyResource
This sample code shows how to call VerifyResource.  
VerifyResource receives an admission request, configuration(ManifestVerifyConfig) and verification rule(ManifestVerifyRule).  
If you use default configuration, it can be `nil`. 
```
import (
    "github.com/stolostron/integrity-shield/shield/pkg/config"
	"github.com/stolostron/integrity-shield/shield/pkg/shield"
	admission "k8s.io/api/admission/v1beta1"
)

func sample(adreq *admission.Request) {
	ruleBytes, err := ioutil.ReadFile("sample-manifest-verify-rule.yml")
	if err != nil {
		fmt.Println(err)
		return
	}

	var rule *config.ManifestVerifyRule
	err = yaml.Unmarshal(ruleBytes, &rule)
	if err != nil {
		fmt.Println(err)
		return
	}

	defaultRuleBytes, err := ioutil.ReadFile("sample-manifest-verify-config.yml")
	if err != nil {
		fmt.Println(err)
		return
	}

	var defaultRule *config.ManifestVerifyConfig
	err = yaml.Unmarshal(defaultRuleBytes, &defaultRule)
	if err != nil {
		fmt.Println(err)
		return
	}

  
  allow, msg, err := shield.VerifyResource(adreq, defaultRule, rule) // verifyResource accepts (adreq, nil, rule) 
	if err != nil {
		fmt.Println(err)
		return
	}
	res := fmt.Sprintf("allow: %s, reaseon: %s", allow, msg)
	fmt.Println(res)
	return
}
```
The following snippets are examples of ManifestVerifyConfig and ManifestVerifyRule.

1. ManifestVerifyRule("sample-manifest-verify-rule.yml")
```yaml
objectSelector:
- name: sample-cm
ignoreFields:
- objects:
  - kind: ConfigMap
  fields:
  - data.comment
keyConfigs:
- key:
    name: keyring
    PEM: |-
      -----BEGIN PGP PUBLIC KEY BLOCK-----

      mQENBF+0ogoBCADiOMDUUXI/dnPjSj1GTJ5pNv6GTzxEEkFNSjzskTyGPwE+D14y
      iZ74BwIsa+n0hZHWfUeGP41oxMxBsTx+F7AHb4i/7SXg8K6Qg07xJgy1Q5fV7m7E
      liVZ9Xso5VqrEyTaa8ipC2DCvSYkWUD3fKR3W5dh18qqr6RCSkMltiIb2IG9DNQS...
      -----END PGP PUBLIC KEY BLOCK-----
```

2. ManifestVerifyConfig("sample-manifest-verify-config.yml")

please check [here](../shield/resource/manifest-verify-config.yaml).