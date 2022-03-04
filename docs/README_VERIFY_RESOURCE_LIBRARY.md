# VerifyResource
VerifyResource is a library which checks if admission request is valid based on signature and verification rule.

# How to VerifyResource
This is the example code to show how to call VerifyResource.
VerifyResource recieves admission request, configuration(ManifestVerifyConfig) and verification rule(ManifestVerifyRule).
If you use default configuration, it can be nil. 
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

1. ManifestVerifyRule
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
      liVZ9Xso5VqrEyTaa8ipC2DCvSYkWUD3fKR3W5dh18qqr6RCSkMltiIb2IG9DNQS
      Hm9KtxR0olgxl6glB20a+W9yoy9Jwgat8RepyBumpKEcAF0+Kz9jR+zVepeagAdX
      b4d+BCnP92y9lb1sPBd0p0EepK3G9RVg2dgV8Lt6nmPRZRQ1ujBG3SS7Gk/VGtUG
      zexAFw5OrIiQ23FXfIdMBVWqmliZG06AmfaxABEBAAG0IlRlc3RTaWduZXIgPHNp
      Z25lckBlbnRlcnByaXNlLmNvbT6JAVQEEwEIAD4WIQRAV4GytKYvpEfFpEj6TtJd
      LICAvwUCX7SiCgIbAwUJA8JnAAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRD6
      TtJdLICAv8+nB/9e4zKZIumLS4Y3e9IFkAry/Cfofi1TAKz1X8eh3ifIaBGwTxNg
      T4ef5y+L2ofHAWBgb/W/ymbaryuL97l+M/c2M7aijygOz3WLY2CNtBSWnU7D4HJH
      +pvKNxcSvQ0cDLRBakWxX/CqwjI+71n1ug037XR4Kb+WfwfcBp5oA2EQOxKjbLj+
      II8N8CTj/YE0YPF4NaH3OnArlUjzGVw7JWpYIYCW/xKdEe/lOjH6fheZvMMLIwEX
      UPiTYpI7UHmLyzBaCQEMtZEML/Fgm81KHKvZJcnUGXC4At4wFFvi+vbUy5ZEeQ+E
      3Sy40mTFkwd7hrx3VdK1v6Za9RNXL17Q6ICWuQENBF+0ogoBCADiTdFnG4F8Zksz
      DhCQtMpuXLG6C43duX3Upfb8q4htp+rpDcy3esacNQu0jVJpnSsDk3F7tRpw+PeC
      TDKpYM6XA6MiHjmtdF+lE76Ay1Q15brc78B/sh9v0N4RmEWe38xbxjqDf5o1dMoq
      HS/cR16pRURJIJhIkvoi28VvCpYhVuKXKz/rC+gox00ZvaQAx8dvgqTvRmpm1/dC
      ayRWdszPsjqGB0rRz9muJbV9HDdPP0p+JCJe/JO3RFpJpVfmxGzx9fRyLc8lYJkg
      dJoB1Vwpk95KYHqXkMv5F5liWGofVE6VIAdYTbammicl7mnXo+RnpwnFPgC86DoG
      cZpyjJEZABEBAAGJATwEGAEIACYWIQRAV4GytKYvpEfFpEj6TtJdLICAvwUCX7Si
      CgIbDAUJA8JnAAAKCRD6TtJdLICAv1eFCACYgkgPbhTxVouKevXr/CtDbZR6GW7g
      FEHpT1PFVxJIjiMSD2xJv8oBswdp+JOffpJCy+B1QgIHI0BphjU33nYRfq/cUStL
      Ih6xEfrnsZLGx0pjuSvAWtNwrObbWeQSSh1P+juUgzG8BpUPsjp8FIV/RmV0HO3L
      FN9TpLhW1mtziU4kPyBgnqaLc2P4JHVKf/RhBl15qmxrBc0IsepT+WTrTEjflfAW
      2GUjbQoAsLs/0qcOowwKOC7FZqxJ7NUuQRp0Kzssx/OPIzZ90uXEqxNd3YVhw0ID
      f+sWpdOji/jIAfAm+nkQ2oxzup1oUAqCqM5HoTpSt//7By+gJXZofa+8
      =MZiY
      -----END PGP PUBLIC KEY BLOCK-----
```

2. ManifestVerifyConfig
please check [here](../shield/resource/manifest-verify-config.yaml)