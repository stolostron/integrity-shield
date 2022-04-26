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
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	kubeutil "github.com/stolostron/integrity-shield/shield/pkg/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kubeclient "k8s.io/client-go/kubernetes"
)

// Parameter in constraint
type ParameterObject struct {
	ConstraintName     string `json:"constraintName"`
	ManifestVerifyRule `json:""`
	ImageProfile       ImageProfile `json:"imageProfile,omitempty"`
	Action             *Action      `json:"action,omitempty"`
	GetProvenance      bool         `json:"getProvenance,omitempty"`
}

type ManifestVerifyRule struct {
	SignatureRef                     SignatureRef                    `json:"signatureRef,omitempty"`
	KeyConfigs                       []KeyConfig                     `json:"keyConfigs,omitempty"`
	InScopeObjects                   k8smanifest.ObjectReferenceList `json:"objectSelector,omitempty"`
	SkipUsers                        ObjectUserBindingList           `json:"skipUsers,omitempty"`
	InScopeUsers                     ObjectUserBindingList           `json:"inScopeUsers,omitempty"`
	k8smanifest.VerifyResourceOption `json:""`
}

// enforce/inform mode
type Action struct {
	Mode          string `json:"mode,omitempty"`
	AdmissionOnly bool   `json:"admissionOnly,omitempty"`
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
	Key    Key       `json:"key,omitempty"`       // PEM encoded public key
	Secret KeySecret `json:"keySecret,omitempty"` // public key as a Kubernetes Secret
}

type Key struct {
	Name string `json:"name,omitempty"`
	PEM  string `json:"PEM,omitempty"`
}

type KeySecret struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Mount     bool   `json:"mount,omitempty"` // if true, save secret data as a file.
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

func (p *ManifestVerifyRule) DeepCopyInto(p2 *ManifestVerifyRule) {
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

// validate ManifestVerifyRule
func ValidateManifestVerifyRule(p *ManifestVerifyRule) error {
	// TODO: fix
	return nil
}

func (k KeyConfig) LoadKeySecret() (string, error) {
	kubeconf, _ := kubeutil.GetKubeConfig()
	clientset, err := kubeclient.NewForConfig(kubeconf)
	if err != nil {
		return "", err
	}
	secret, err := clientset.CoreV1().Secrets(k.Secret.Namespace).Get(context.Background(), k.Secret.Name, metav1.GetOptions{})
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed to get a secret `%s` in `%s` namespace", k.Secret.Namespace, k.Secret.Name))
	}
	keyDir := fmt.Sprintf("/tmp/%s/%s/", k.Secret.Namespace, k.Secret.Name)
	sumErr := []string{}
	keyPath := ""
	for fname, keyData := range secret.Data {
		err := os.MkdirAll(keyDir, os.ModePerm)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		fpath := filepath.Join(keyDir, fname)
		err = ioutil.WriteFile(fpath, keyData, 0644)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		keyPath = fpath
		break
	}
	if keyPath == "" && len(sumErr) > 0 {
		return "", errors.New(fmt.Sprintf("failed to save secret data as a file; %s", strings.Join(sumErr, "; ")))
	}
	if keyPath == "" {
		return "", errors.New(fmt.Sprintf("no key files are found in the secret `%s` in `%s` namespace", k.Secret.Namespace, k.Secret.Name))
	}

	return keyPath, nil
}

func (k KeyConfig) ConvertToCosignKeyRef() string {
	ref := fmt.Sprintf("k8s://%s/%s", k.Secret.Namespace, k.Secret.Name)
	return ref
}

func (k KeyConfig) ConvertToLocalFilePath() (string, error) {
	dir, err := ioutil.TempDir("", k.Key.Name)
	if err != nil {
		return "", errors.New(fmt.Sprintf("failed to make temp dir for PEM public key; %s; %s", dir, err))
	}
	fpath := filepath.Join(dir, "key.pub")
	err = ioutil.WriteFile(fpath, []byte(k.Key.PEM), 0644)
	if err != nil {
		return "", errors.New(fmt.Sprintf("failed to save PEM public key as a file; %s; %s", fpath, err))
	}

	return fpath, nil
}

func ClearLocalFile(fpath string) {
	dir := strings.Replace(fpath, "key.pub", "", 1)
	defer os.RemoveAll(dir)
}
