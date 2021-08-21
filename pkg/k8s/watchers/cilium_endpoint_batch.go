//  Copyright 2021 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package watchers

import (
	"sync"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var (
	cebNotify = subscriber.NewRaw()
)

func (k *K8sWatcher) ciliumEndpointBatchInit(client *k8s.K8sCiliumClient, asyncControllers *sync.WaitGroup) {
	log.Info("Initializing CEB controller")
	var once sync.Once

	// Register for all ceb updates.
	cebNotify.Register(newCEBSubscriber(k))

	_, cebController := informer.NewInformer(
		cache.NewListWatchFromClient(client.CiliumV2alpha1().RESTClient(),
			cilium_v2a1.CEBPluralName, v1.NamespaceAll, fields.Everything()),
		&cilium_v2a1.CiliumEndpointBatch{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if ceb := k8s.ObjToCiliumEndpointBatch(obj); ceb != nil {
					cebNotify.NotifyAdd(ceb)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldCeb := k8s.ObjToCiliumEndpointBatch(oldObj); oldCeb != nil {
					if newCeb := k8s.ObjToCiliumEndpointBatch(newObj); newCeb != nil {
						if oldCeb.DeepEqual(newCeb) {
							return
						}
						cebNotify.NotifyUpdate(oldCeb, newCeb)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				if ceb := k8s.ObjToCiliumEndpointBatch(obj); ceb != nil {
					cebNotify.NotifyDelete(ceb)
				}
			},
		},
		nil,
	)
	once.Do(func() {
		// Signalize that we have put node controller in the wait group
		// to sync resources.
		asyncControllers.Done()
	})
	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		cebController.HasSynced,
		k8sAPIGroupCiliumEndpointBatchV2Alpha1,
	)

	go cebController.Run(wait.NeverStop)
}
