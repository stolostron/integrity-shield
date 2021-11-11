//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package config

import (
	"github.com/jinzhu/copier"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type ParameterObject struct {
	ConstraintName                   string                          `json:"constraintName"`
	SignatureRef                     SignatureRef                    `json:"signatureRef,omitempty"`
	KeyConfigs                       []KeyConfig                     `json:"keyConfigs,omitempty"`
	InScopeObjects                   k8smanifest.ObjectReferenceList `json:"objectSelector,omitempty"`
	SkipUsers                        ObjectUserBindingList           `json:"skipUsers,omitempty"`
	InScopeUsers                     ObjectUserBindingList           `json:"inScopeUsers,omitempty"`
	ImageProfile                     ImageProfile                    `json:"imageProfile,omitempty"`
	k8smanifest.VerifyResourceOption `json:""`
	Action                           *Action `json:"action,omitempty"`
	GetProvenance                    bool    `json:"getProvenance,omitempty"`
}

type Action struct {
	Mode string `json:"mode,omitempty"`
}

type SignatureRef struct {
	ImageRef              string      `json:"imageRef,omitempty"`
	SignatureResourceRef  ResourceRef `json:"signatureResourceRef,omitempty"`
	ProvenanceResourceRef ResourceRef `json:"provenanceResourceRef,omitempty"`
}

type ResourceRef struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type KeyConfig struct {
	KeySecretName      string `json:"keySecretName,omitempty"`
	KeySecretNamespace string `json:"keySecretNamespace,omitempty"`
}

type ImageRef string
type ImageRefList []ImageRef

func (l ImageRefList) Match(imageRef string) bool {
	if len(l) == 0 {
		return true
	}
	for _, r := range l {
		if r.Match(imageRef) {
			return true
		}
	}
	return false
}

func (r ImageRef) Match(imageRef string) bool {
	return k8smnfutil.MatchPattern(string(r), imageRef)
}

type ObjectUserBindingList []ObjectUserBinding

type ObjectUserBinding struct {
	Objects k8smanifest.ObjectReferenceList `json:"objects,omitempty"`
	Users   []string                        `json:"users,omitempty"`
}

type ImageProfile struct {
	KeyConfigs []KeyConfig  `json:"keyConfigs,omitempty"`
	Match      ImageRefList `json:"match,omitempty"`
	Exclude    ImageRefList `json:"exclude,omitempty"`
}

func (p *ParameterObject) DeepCopyInto(p2 *ParameterObject) {
	_ = copier.Copy(&p2, &p)
}

func (u ObjectUserBinding) Match(obj unstructured.Unstructured, username string) bool {
	if u.Objects.Match(obj) {
		if k8smnfutil.MatchWithPatternArray(username, u.Users) {
			return true
		}
	}
	return false
}

func (l ObjectUserBindingList) Match(obj unstructured.Unstructured, username string) bool {
	if len(l) == 0 {
		return false
	}
	for _, u := range l {
		if u.Match(obj, username) {
			return true
		}
	}
	return false
}

// if any profile condition is defined, image profile returns enabled = true
func (p ImageProfile) Enabled() bool {
	return len(p.Match) > 0 || len(p.Exclude) > 0
}

// returns if this profile matches the specified image ref or not
func (p ImageProfile) MatchWith(imageRef string) bool {
	matched := p.Match.Match(imageRef)
	excluded := false
	if len(p.Exclude) > 0 {
		excluded = p.Exclude.Match(imageRef)
	}
	return matched && !excluded
}
