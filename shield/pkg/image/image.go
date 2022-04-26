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

package image

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/manifest"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
	ishieldconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type ImageVerifyResult struct {
	Object     unstructured.Unstructured `json:"object"`
	ImageRef   string                    `json:"imageRef"`
	Verified   bool                      `json:"verified"`
	InScope    bool                      `json:"inScope"`
	Signer     string                    `json:"signer"`
	SignedTime *time.Time                `json:"signedTime"`
	FailReason string                    `json:"failReason"`
}

type ImageVerifyOption struct {
	KeyPath string
}

// verify all images in a container of the specified resource
func VerifyImageInManifest(resource unstructured.Unstructured, profile ishieldconfig.ImageProfile) (bool, error) {
	yamlBytes, err := yaml.Marshal(resource.Object)
	if err != nil {
		return false, errors.Wrap(err, "failed to yaml.Marshal() the resource")
	}
	tmpDir, err := ioutil.TempDir("", "verify-image")
	if err != nil {
		return false, fmt.Errorf("failed to create temp dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpDir)

	manifestPath := filepath.Join(tmpDir, "manifest.yaml")
	err = ioutil.WriteFile(manifestPath, yamlBytes, 0644)
	if err != nil {
		return false, fmt.Errorf("failed to create temp manifest file: %s", err.Error())
	}

	keyPathList := []string{}
	if len(profile.KeyConfigs) != 0 {
		for _, keyconfig := range profile.KeyConfigs {
			if keyconfig.Secret.Namespace != "" && keyconfig.Secret.Name != "" {
				if keyconfig.Secret.Mount {
					keyPath, err := keyconfig.LoadKeySecret()
					if err != nil {
						return false, fmt.Errorf("Failed to load key secret: %s", err.Error())
					}
					keyPathList = append(keyPathList, keyPath)
				} else {
					keyRef := keyconfig.ConvertToCosignKeyRef()
					keyPathList = append(keyPathList, keyRef)
				}
			}
			if keyconfig.Key.PEM != "" && keyconfig.Key.Name != "" {
				keyPath, err := keyconfig.ConvertToLocalFilePath(tmpDir)
				if err != nil {
					return false, fmt.Errorf("Failed to get local file path: %s", err.Error())
				}
				keyPathList = append(keyPathList, keyPath)
			}
		}
	}
	if len(keyPathList) == 0 {
		keyPathList = []string{""} // for keyless verification
	}

	allImagesVerified := false
	failReason := ""
	// overallFailReason := ""
	for _, keyPath := range keyPathList {
		cmd := manifest.VerifyManifestCommand{VerifyCommand: verify.VerifyCommand{}}
		if keyPath != "" {
			cmd.KeyRef = keyPath
		}

		var verifiedWithThisKey bool
		// currently cosigncli.VerifyManifestCommand.Exec() does not return detail information like image names and their signer names
		// TODO: create an issue in sigstore/cosign for this function to return some additional information
		iErr := cmd.Exec(context.Background(), []string{manifestPath})
		if iErr == nil {
			verifiedWithThisKey = true
		} else {
			failReason = iErr.Error()
		}
		if verifiedWithThisKey {
			allImagesVerified = true
			break
		}
	}

	var retErr error
	if !allImagesVerified {
		retErr = errors.New(failReason)
	}

	return allImagesVerified, retErr
}
