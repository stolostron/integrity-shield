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

package observer

import (
	"context"

	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// groupResource contains the APIGroup and APIResource
type groupResource struct {
	APIGroup    string             `json:"apiGroup"`
	APIVersion  string             `json:"apiVersion"`
	APIResource metav1.APIResource `json:"resource"`
}

type groupResourceWithTargetNS struct {
	groupResource    `json:""`
	TargetNamespaces []string `json:"targetNamespace"`
}

func (self *Observer) getAPIResources(kubeconfig *rest.Config) error {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(kubeconfig)
	if err != nil {
		return err
	}

	apiResourceLists, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		return err
	}
	resources := []groupResource{}
	for _, apiResourceList := range apiResourceLists {
		if len(apiResourceList.APIResources) == 0 {
			continue
		}
		gv, err := schema.ParseGroupVersion(apiResourceList.GroupVersion)
		if err != nil {
			continue
		}
		for _, resource := range apiResourceList.APIResources {
			if !Contains(resource.Verbs, "list") {
				continue
			}
			if !Contains(IgnoredKinds, resource.Kind) {
				resources = append(resources, groupResource{
					APIGroup:    gv.Group,
					APIVersion:  gv.Version,
					APIResource: resource,
				})
			}
		}
	}
	self.APIResources = resources
	return nil
}

func (self *Observer) getNamespaces(kubeconfig *rest.Config) error {
	clientset, err := kubeclient.NewForConfig(kubeconfig)
	if err != nil {
		return err
	}
	namespaces, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("failed to list a namespace:`%s`", err.Error())
		return err
	}
	var nslist []string
	for _, ns := range namespaces.Items {
		nslist = append(nslist, ns.Name)
	}
	self.Namespaces = nslist
	return nil
}

func (self *Observer) getAllResoucesByGroupResource(gResourceWithTargetNS groupResourceWithTargetNS, labelSelector *metav1.LabelSelector) ([]unstructured.Unstructured, error) {
	var resources []unstructured.Unstructured
	var err error
	gResource := gResourceWithTargetNS.groupResource
	targetNSs := gResourceWithTargetNS.TargetNamespaces
	namespaced := gResource.APIResource.Namespaced
	gvr := schema.GroupVersionResource{
		Group:    gResource.APIGroup,
		Version:  gResource.APIVersion,
		Resource: gResource.APIResource.Name,
	}
	listOptions := metav1.ListOptions{}
	if labelSelector != nil {
		listOptions = metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(labelSelector)}
	}
	var tmpResourceList *unstructured.UnstructuredList
	if namespaced {
		for _, ns := range targetNSs {
			tmpResourceList, err = self.DynamicClient.Resource(gvr).Namespace(ns).List(context.Background(), listOptions)
			if err != nil {
				log.Errorf("failed to get tmpResourceList %s in %s; err: %s", gvr, ns, err.Error())
				continue
			}
			resources = append(resources, tmpResourceList.Items...)
		}

	} else {
		tmpResourceList, err = self.DynamicClient.Resource(gvr).List(context.Background(), listOptions)
		if err != nil {
			log.Errorf("failed to get cluster scoped tmpResourceList %s; err: %s", gvr, err.Error())
		} else {
			resources = append(resources, tmpResourceList.Items...)
		}
	}
	return resources, nil
}

func (self *Observer) getPossibleProtectedGVKs(match MatchCondition) []groupResourceWithTargetNS {
	possibleProtectedGVKs := []groupResourceWithTargetNS{}
	for _, apiResource := range self.APIResources {
		matched := self.checkIfRuleMatchWithGVK(match, apiResource)
		if matched {
			matchedNamespaces := self.getMathedNamespaces(match)
			tmpGvks := self.getGroupResourceWithTargetNS(apiResource, matchedNamespaces)
			possibleProtectedGVKs = append(possibleProtectedGVKs, tmpGvks...)
		}
	}
	return possibleProtectedGVKs
}

func (self *Observer) checkIfRuleMatchWithGVK(match MatchCondition, apiResource groupResource) bool {
	matched := false
	// kind
	if len(match.Kinds) != 0 {
		for _, kinds := range match.Kinds {
			kmatch := false
			agmatch := false
			if len(kinds.ApiGroups) != 0 {
				agmatch = Contains(kinds.ApiGroups, apiResource.APIGroup)
			} else {
				agmatch = true
			}
			if len(kinds.ApiGroups) != 0 {
				kmatch = Contains(kinds.Kinds, apiResource.APIResource.Kind)
			} else {
				kmatch = true
			}
			if kmatch && agmatch {
				matched = true
			}
		}
	} else {
		matched = true
	}
	return matched
}

func (self *Observer) getMathedNamespaces(match MatchCondition) []string {
	// namespace
	var matchedNamespaces []string
	if len(match.Namespaces) == 0 {
		if match.NamespaceSelector != nil {
			labeledNS := self.getLabelMatchedNamespace(match.NamespaceSelector)
			if match.ExcludedNamespaces != nil {
				excludedNs := self.listAllMatchedNamespaces(match.ExcludedNamespaces)
				labeledNS = self.checkExcludedNamespace(excludedNs, labeledNS)
			}
			matchedNamespaces = labeledNS
		} else {
			if match.ExcludedNamespaces != nil {
				targetNs := self.Namespaces
				excludedNs := self.listAllMatchedNamespaces(match.ExcludedNamespaces)
				targetNs = self.checkExcludedNamespace(excludedNs, targetNs)
				matchedNamespaces = targetNs
			} else {
				matchedNamespaces = self.Namespaces
			}
		}
	} else {
		// len(match.Namespaces) != 0
		targetNs := self.listAllMatchedNamespaces(match.Namespaces)
		if match.ExcludedNamespaces != nil {
			excludedNs := self.listAllMatchedNamespaces(match.ExcludedNamespaces)
			targetNs = self.checkExcludedNamespace(excludedNs, targetNs)
		}
		matchedNamespaces = targetNs
	}
	return matchedNamespaces
}

func (self *Observer) getGroupResourceWithTargetNS(apiResource groupResource, matchedNamespaces []string) []groupResourceWithTargetNS {
	possibleProtectedGVKs := []groupResourceWithTargetNS{}
	if !apiResource.APIResource.Namespaced {
		if len(matchedNamespaces) == 0 {
			possibleProtectedGVKs = append(possibleProtectedGVKs, groupResourceWithTargetNS{
				groupResource: apiResource,
			})
		}
	} else {
		possibleProtectedGVKs = append(possibleProtectedGVKs, groupResourceWithTargetNS{
			groupResource:    apiResource,
			TargetNamespaces: matchedNamespaces,
		})
	}
	return possibleProtectedGVKs
}

func Contains(pattern []string, value string) bool {
	for _, p := range pattern {
		if p == value {
			return true
		}
	}
	return false
}

func (self *Observer) getLabelMatchedNamespace(labelSelector *metav1.LabelSelector) []string {
	matchedNs := []string{}
	if labelSelector == nil {
		return []string{}
	}

	namespaces, err := self.Clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(labelSelector)})
	if err != nil {
		log.Errorf("failed to list a namespace:`%s`", err.Error())
		return []string{}
	}
	for _, ns := range namespaces.Items {
		matchedNs = append(matchedNs, ns.Name)
	}
	return matchedNs
}

func (self *Observer) checkExcludedNamespace(excludedNamespaces []string, targetNamespaces []string) []string {
	matchedNs := []string{}
	for _, ns := range targetNamespaces {
		if !Contains(excludedNamespaces, ns) {
			matchedNs = append(matchedNs, ns)
		}
	}
	return matchedNs
}

// creating a simple namespace list considering wildcard rules
func (self *Observer) listAllMatchedNamespaces(rule []string) []string {
	matchedNs := []string{}
	if rule == nil {
		return matchedNs
	}
	for _, ns := range self.Namespaces {
		excluded := k8smnfutil.MatchWithPatternArray(ns, rule)
		if excluded {
			matchedNs = append(matchedNs, ns)
		}
	}
	return matchedNs
}
