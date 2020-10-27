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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcerconfig/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeEnforcerConfigs implements EnforcerConfigInterface
type FakeEnforcerConfigs struct {
	Fake *FakeResearchV1alpha1
	ns   string
}

var enforcerconfigsResource = schema.GroupVersionResource{Group: "research.ibm.com", Version: "v1alpha1", Resource: "enforcerconfigs"}

var enforcerconfigsKind = schema.GroupVersionKind{Group: "research.ibm.com", Version: "v1alpha1", Kind: "EnforcerConfig"}

// Get takes name of the enforcerConfig, and returns the corresponding enforcerConfig object, and an error if there is any.
func (c *FakeEnforcerConfigs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.EnforcerConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(enforcerconfigsResource, c.ns, name), &v1alpha1.EnforcerConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.EnforcerConfig), err
}

// List takes label and field selectors, and returns the list of EnforcerConfigs that match those selectors.
func (c *FakeEnforcerConfigs) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.EnforcerConfigList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(enforcerconfigsResource, enforcerconfigsKind, c.ns, opts), &v1alpha1.EnforcerConfigList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.EnforcerConfigList{ListMeta: obj.(*v1alpha1.EnforcerConfigList).ListMeta}
	for _, item := range obj.(*v1alpha1.EnforcerConfigList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested enforcerConfigs.
func (c *FakeEnforcerConfigs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(enforcerconfigsResource, c.ns, opts))

}

// Create takes the representation of a enforcerConfig and creates it.  Returns the server's representation of the enforcerConfig, and an error, if there is any.
func (c *FakeEnforcerConfigs) Create(ctx context.Context, enforcerConfig *v1alpha1.EnforcerConfig, opts v1.CreateOptions) (result *v1alpha1.EnforcerConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(enforcerconfigsResource, c.ns, enforcerConfig), &v1alpha1.EnforcerConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.EnforcerConfig), err
}

// Update takes the representation of a enforcerConfig and updates it. Returns the server's representation of the enforcerConfig, and an error, if there is any.
func (c *FakeEnforcerConfigs) Update(ctx context.Context, enforcerConfig *v1alpha1.EnforcerConfig, opts v1.UpdateOptions) (result *v1alpha1.EnforcerConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(enforcerconfigsResource, c.ns, enforcerConfig), &v1alpha1.EnforcerConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.EnforcerConfig), err
}

// Delete takes name of the enforcerConfig and deletes it. Returns an error if one occurs.
func (c *FakeEnforcerConfigs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(enforcerconfigsResource, c.ns, name), &v1alpha1.EnforcerConfig{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeEnforcerConfigs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(enforcerconfigsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.EnforcerConfigList{})
	return err
}

// Patch applies the patch and returns the patched enforcerConfig.
func (c *FakeEnforcerConfigs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.EnforcerConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(enforcerconfigsResource, c.ns, name, pt, data, subresources...), &v1alpha1.EnforcerConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.EnforcerConfig), err
}
