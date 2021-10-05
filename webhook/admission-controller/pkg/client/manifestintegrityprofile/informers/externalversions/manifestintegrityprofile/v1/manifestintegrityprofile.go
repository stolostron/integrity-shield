/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by informer-gen. DO NOT EDIT.

package v1

import (
	"context"
	time "time"

	manifestintegrityprofilev1 "github.com/IBM/integrity-enforcer/webhook/admission-controller/pkg/apis/manifestintegrityprofile/v1"
	versioned "github.com/IBM/integrity-enforcer/webhook/admission-controller/pkg/client/manifestintegrityprofile/clientset/versioned"
	internalinterfaces "github.com/IBM/integrity-enforcer/webhook/admission-controller/pkg/client/manifestintegrityprofile/informers/externalversions/internalinterfaces"
	v1 "github.com/IBM/integrity-enforcer/webhook/admission-controller/pkg/client/manifestintegrityprofile/listers/manifestintegrityprofile/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// ManifestIntegrityProfileInformer provides access to a shared informer and lister for
// ManifestIntegrityProfiles.
type ManifestIntegrityProfileInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.ManifestIntegrityProfileLister
}

type manifestIntegrityProfileInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewManifestIntegrityProfileInformer constructs a new informer for ManifestIntegrityProfile type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewManifestIntegrityProfileInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredManifestIntegrityProfileInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredManifestIntegrityProfileInformer constructs a new informer for ManifestIntegrityProfile type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredManifestIntegrityProfileInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ApisV1().ManifestIntegrityProfiles().List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ApisV1().ManifestIntegrityProfiles().Watch(context.TODO(), options)
			},
		},
		&manifestintegrityprofilev1.ManifestIntegrityProfile{},
		resyncPeriod,
		indexers,
	)
}

func (f *manifestIntegrityProfileInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredManifestIntegrityProfileInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *manifestIntegrityProfileInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&manifestintegrityprofilev1.ManifestIntegrityProfile{}, f.defaultInformer)
}

func (f *manifestIntegrityProfileInformer) Lister() v1.ManifestIntegrityProfileLister {
	return v1.NewManifestIntegrityProfileLister(f.Informer().GetIndexer())
}
