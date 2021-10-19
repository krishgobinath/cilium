// Copyright 2017-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by informer-gen. DO NOT EDIT.

package externalversions

import (
	"fmt"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	cache "k8s.io/client-go/tools/cache"
)

// GenericInformer is type of SharedIndexInformer which will locate and delegate to other
// sharedInformers based on type
type GenericInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() cache.GenericLister
}

type genericInformer struct {
	informer cache.SharedIndexInformer
	resource schema.GroupResource
}

// Informer returns the SharedIndexInformer.
func (f *genericInformer) Informer() cache.SharedIndexInformer {
	return f.informer
}

// Lister returns the GenericLister.
func (f *genericInformer) Lister() cache.GenericLister {
	return cache.NewGenericLister(f.Informer().GetIndexer(), f.resource)
}

// ForResource gives generic access to a shared informer of the matching type
// TODO extend this to unknown resources with a client pool
func (f *sharedInformerFactory) ForResource(resource schema.GroupVersionResource) (GenericInformer, error) {
	switch resource {
	// Group=cilium.io, Version=v2
	case v2.SchemeGroupVersion.WithResource("ciliumclusterwidenetworkpolicies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Cilium().V2().CiliumClusterwideNetworkPolicies().Informer()}, nil
	case v2.SchemeGroupVersion.WithResource("ciliumendpoints"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Cilium().V2().CiliumEndpoints().Informer()}, nil
	case v2.SchemeGroupVersion.WithResource("ciliumexternalworkloads"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Cilium().V2().CiliumExternalWorkloads().Informer()}, nil
	case v2.SchemeGroupVersion.WithResource("ciliumidentities"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Cilium().V2().CiliumIdentities().Informer()}, nil
	case v2.SchemeGroupVersion.WithResource("ciliumlocalredirectpolicies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Cilium().V2().CiliumLocalRedirectPolicies().Informer()}, nil
	case v2.SchemeGroupVersion.WithResource("ciliumnetworkpolicies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Cilium().V2().CiliumNetworkPolicies().Informer()}, nil
	case v2.SchemeGroupVersion.WithResource("ciliumnodes"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Cilium().V2().CiliumNodes().Informer()}, nil

		// Group=cilium.io, Version=v2alpha1
	case v2alpha1.SchemeGroupVersion.WithResource("ciliumegressnatpolicies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Cilium().V2alpha1().CiliumEgressNATPolicies().Informer()}, nil
	case v2alpha1.SchemeGroupVersion.WithResource("ciliumendpointslices"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Cilium().V2alpha1().CiliumEndpointSlices().Informer()}, nil

	}

	return nil, fmt.Errorf("no informer found for %v", resource)
}
