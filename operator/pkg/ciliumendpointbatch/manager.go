// Copyright 2021 Authors of Cilium
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

package ciliumendpointbatch

import (
	"fmt"
	"math/rand"
	"time"

	"k8s.io/client-go/util/workqueue"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/sirupsen/logrus"
)

var (
	// sequentialLetters contains lower case alphabets without vowels and few numbers.
	// skipped vowels and numbers [0, 1] to avoid generating controversial names.
	sequentialLetters = []rune("bcdfghjklmnpqrstvwxyz2456789")
)

// cebTracker holds the desired state of CiliumEndpointBatch and list of ceps to be removed
// in next sync with k8s-apiserver.
type cebTracker struct {
	// Mutex to protect cep insert/removal in ceb and removedCeps
	backendMutex lock.RWMutex
	// The desired state of ceb object
	ceb *cilium_v2.CiliumEndpointBatch
	// set of CEPs to be removed in the CEB object in next sync.
	removedCeps map[string]struct{}
}

// cebManager
type cebManager interface {
	// External APIs to Insert/Remove CEP in local dataStore
	InsertCepInCache(cep *cilium_v2.CoreCiliumEndpoint) string
	RemoveCepFromCache(cepName string)
	// Supporting APIs to Insert/Remove CEP in local dataStore and effectively
	// manages CEB's.
	getCebFromCache(cebName string) (*cilium_v2.CiliumEndpointBatch, error)
	getCebCopyFromCache(cebName string) (*cilium_v2.CiliumEndpointBatch, error)
	findCeb(cep *cilium_v2.CoreCiliumEndpoint) *cebTracker
	updateCebInCache(ceb *cilium_v2.CiliumEndpointBatch, deepCopy bool)
	deleteCebFromCache(cebName string)
	getRemovedCeps(string) map[string]struct{}
	clearRemovedCeps(string, map[string]struct{})
	createCeb(cebName string) *cebTracker
	// APIs to collect metrics of CEB and CEP
	getTotalCepCount() int
	getCepCountInCeb(cebName string) int
	getCebCount() int
	getAllCepNames() []string
}

// Implementation of FirstComeFirstServe batching mode. If new CEP is inserted,
// then the CEP is queued in any one of the available CEB. CEPs are inserted into
// CEBs without any preference or any priority.
type cebMgr struct {

	// cacheCepMap is used to map cepName to cebName
	cacheCepMap *cepToCebMapping

	// desiredCebs is used to map cebName to cebTracker object.
	// TODO: protect access to desiredCebs with lock.
	desiredCebs map[string]*cebTracker

	// workqueue is used to sync CEBs with the api-server. this will rate-limit the
	// CEB requests going to api-server, ensures a single CEB will not be proccessed
	// multiple times concurrently, and if CEB is added multiple times before it
	// can be processed, this will only be processed only once.
	queue workqueue.RateLimitingInterface

	// maxCepsInCeb is the maximum number of CiliumCoreEndpoint(s) packed in
	// a CiliumEndpointBatch Resource.
	maxCepsInCeb int
}

type cebManagerFcfs struct {
	cebMgr
}

type cebManagerIdentity struct {
	cebMgr
	identityToCeb map[int64][]*cebTracker
}

// newCebManagerFcfs creates and initializes a new FCFS based manager.
func newCebManagerFcfs(workQueue workqueue.RateLimitingInterface, maxCepsInCeb int) cebManager {
	return &cebManagerFcfs{
		cebMgr{
			desiredCebs:  make(map[string]*cebTracker),
			queue:        workQueue,
			cacheCepMap:  newCepToCebMapping(),
			maxCepsInCeb: maxCepsInCeb,
		},
	}
}

// newCebManagerIdentity creates and initializes a new Identity based manager.
func newCebManagerIdentity(workQueue workqueue.RateLimitingInterface, maxCepsInCeb int) cebManager {

	c := cebMgr{
		desiredCebs:  make(map[string]*cebTracker),
		queue:        workQueue,
		cacheCepMap:  newCepToCebMapping(),
		maxCepsInCeb: maxCepsInCeb,
	}
	return &cebManagerIdentity{
		cebMgr:        c,
		identityToCeb: make(map[int64][]*cebTracker),
	}
}

// addCEPtoCEB inserts the CEP in a CEB, if the CEP already exists in a CEB
// it replaces with new CEP.
func addCEPtoCEB(cep *cilium_v2.CoreCiliumEndpoint, cebTracker *cebTracker) {

	cebTracker.backendMutex.Lock()
	defer cebTracker.backendMutex.Unlock()
	// If cep already exists in ceb, compare new cep with cached cep.
	// Update only if there is any change.
	log.WithFields(logrus.Fields{
		"cep-name":        cep.Name,
		"ceb-name":        cebTracker.ceb.GetName(),
		"total cep-count": len(cebTracker.ceb.Endpoints),
	}).Debug("Queueing cep in ceb")

	for i, ep := range cebTracker.ceb.Endpoints {
		if GetCepNameFromCCEP(&ep) == GetCepNameFromCCEP(cep) {
			if cep.DeepEqual(&ep) {
				return
			}
			// Remove the matched cep from ceb endpoints list.
			cebTracker.ceb.Endpoints =
				append(cebTracker.ceb.Endpoints[:i], cebTracker.ceb.Endpoints[i+1:]...)
			break
		}
	}

	// Insert the cep in ceb endpoints list.
	cebTracker.ceb.Endpoints = append(cebTracker.ceb.Endpoints, *cep)
	// If this CEP is re-generated again before previous CEP-DELETE completed.
	// remove this from removedCep list.
	if _, ok := cebTracker.removedCeps[GetCepNameFromCCEP(cep)]; ok {
		delete(cebTracker.removedCeps, GetCepNameFromCCEP(cep))
	}

	return
}

// Generate random string for given length of characters.
func randomName(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = sequentialLetters[rand.Intn(len(sequentialLetters))]
	}
	return string(b)
}

// Generates unique random name for the CiliumEndpointBatch, the format
// of a CEB name is similar to pod k8s naming convention "ceb-123456789-abcde".
// First 3 letters indicates ceb resource, followed by random letters.
func uniqueCeBatchName(desiredCebs map[string]*cebTracker) string {
	rand.Seed(time.Now().UnixNano())
	var exists bool
	var cebName string

	for {
		cebName = fmt.Sprintf("%s-%s-%s", cebNamePrefix, randomName(9), randomName(5))
		if _, exists = desiredCebs[cebName]; !exists {
			return cebName
		}
	}
}

// This function create a new ceb and capacity to hold maximum ceps in a CEB.
//  called on 2 different scenarios.
// 1) During runtime, when ceb manager decides to create a new ceb, it calls
//    with an empty name, it generates a random unique name and assign it to the CEB.
// 2) During operator warm boot [after crash or software upgrade], batching manager
//    creates a CEB, by passing unique name.
func (c *cebMgr) createCeb(name string) *cebTracker {
	var cebName string = name
	if name == "" {
		cebName = uniqueCeBatchName(c.desiredCebs)
	}
	ceb := &cebTracker{
		ceb: &cilium_v2.CiliumEndpointBatch{
			TypeMeta: meta_v1.TypeMeta{
				Kind:       "CiliumEndpointBatch",
				APIVersion: cilium_v2.SchemeGroupVersion.String(),
			},
			ObjectMeta: meta_v1.ObjectMeta{
				Name: cebName,
			},
			Endpoints: make([]cilium_v2.CoreCiliumEndpoint, 0, c.maxCepsInCeb),
		},
		removedCeps: make(map[string]struct{}),
	}
	c.desiredCebs[cebName] = ceb
	log.WithFields(logrus.Fields{
		"ceb-name": cebName,
	}).Debug("Generated ceb")
	return ceb
}

// If exists, remove Ceb object from cache. deleteCebFromCache is called after successful removal from
// apiserver.
func (c *cebMgr) deleteCebFromCache(cebName string) {
	log.Infof("deletceb cebMgr called")
	if _, ok := c.desiredCebs[cebName]; !ok {
		log.WithFields(logrus.Fields{
			"ceb-name": cebName,
		}).Debug("Failed to retrieve Ceb object in local cache.")
		return
	}
	delete(c.desiredCebs, cebName)
}

// updateCebInCache function copies the ciliumEndpoint object in local cache. if isDeepCopy flag is set,
// whole CoreCiliumEndpoint object stored in local cache.
// There are two scenarios updateCebInCache is called.
// 1) During operator warm boot[after crash or software upgrade], CEB controller sync CEB states from
// api-server to cache. In this case, isDeepCopy set to true to copy entire CEP object locally.
// 2) During runtime, reconciler sync current state with API server and update metadata only.
// isDeepCopy flag is set to false.
func (c *cebMgr) updateCebInCache(srcCeb *cilium_v2.CiliumEndpointBatch, isDeepCopy bool) {
	if ceb, ok := c.desiredCebs[srcCeb.GetName()]; ok {
		ceb.backendMutex.Lock()
		if !isDeepCopy {
			ceb.ceb.ObjectMeta = srcCeb.ObjectMeta
		} else {
			ceb.ceb = srcCeb
			for _, cep := range ceb.ceb.Endpoints {
				// Update the cacheCepMap, to reflect all CEPs are packed in a CEB
				c.cacheCepMap.insert(GetCepNameFromCCEP(&cep), srcCeb.GetName())
			}
		}
		ceb.backendMutex.Unlock()
	}
}

// If available, getCebFromCache returns CiliumEndpointBatch object.
func (c *cebMgr) getCebFromCache(cebName string) (*cilium_v2.CiliumEndpointBatch, error) {
	if ceb, exists := c.desiredCebs[cebName]; exists {
		return ceb.ceb, nil
	}
	return nil, fmt.Errorf("Failed to get CEB from local cache for the cebName: %s", cebName)
}

// getCebCopyFromCache returns the copy of CiliumEndpointBatch object.
func (c *cebMgr) getCebCopyFromCache(cebName string) (*cilium_v2.CiliumEndpointBatch, error) {
	if ceb, exists := c.desiredCebs[cebName]; exists {
		outCeb := new(cilium_v2.CiliumEndpointBatch)
		ceb.backendMutex.RLock()
		ceb.ceb.DeepCopyInto(outCeb)
		ceb.backendMutex.RUnlock()
		return outCeb, nil

	}
	return nil, fmt.Errorf("Failed to get CEB Copy from local cache for the cebName: %s", cebName)
}

// findCeb returns the available cebTracker object and is chosen based on FCFS.
// if all CEB's reached max capacity or marked for delete. Allocate a new CEB.
func (c *cebMgr) findCeb(cep *cilium_v2.CoreCiliumEndpoint) (ceb *cebTracker) {

	log.Infof("findCeb cebMgr called")
	// get first available CEB
	for _, ceb = range c.desiredCebs {
		ceb.backendMutex.RLock()
		if len(ceb.ceb.Endpoints) >= c.maxCepsInCeb || len(ceb.ceb.Endpoints) == 0 {
			ceb.backendMutex.RUnlock()
			continue
		}
		ceb.backendMutex.RUnlock()
		return
	}

	// allocate a new cebTracker and return
	ceb = c.createCeb("")
	return
}

// InsertCepInCache is used to Insert CEP in local cache, this may result in Creating a New
// CEB object or Updating an existing CEB object.
func (c *cebMgr) InsertCepInCache(cep *cilium_v2.CoreCiliumEndpoint) string {

	// check the given cep is already exists in any of the CEB.
	// if yes, Update a ceb with the given cep object.
	if cebName, exists := c.cacheCepMap.get(GetCepNameFromCCEP(cep)); exists {
		// add a cep into the ceb
		addCEPtoCEB(cep, c.desiredCebs[cebName])
		c.queue.Add(cebName)
		return cebName
	}

	// If given cep object isn't packed in any of the CEB. find a new ceb
	// to pack this cep.
	cb := c.findCeb(cep)

	// Cache CEP name with newly allocated CEB.
	c.cacheCepMap.insert(GetCepNameFromCCEP(cep), cb.ceb.GetName())

	// Queue the CEP in CEB
	addCEPtoCEB(cep, cb)
	c.queue.Add(cb.ceb.GetName())
	return cb.ceb.GetName()
}

// RemoveCepFromCache is used to remove the CEP from local cache, this may result in
// Updating an existing CEB object.
func (c *cebMgr) RemoveCepFromCache(cepName string) {

	log.WithFields(logrus.Fields{
		"cep-name": cepName,
	}).Debug("Remove CEP from local cache")

	// Check in local cache, if a given cep is already batched in one of the ceb.
	// and if exists, delete cep from ceb.
	if cebName, exists := c.cacheCepMap.get(cepName); exists {
		var ceb *cebTracker
		if ceb, exists = c.desiredCebs[cebName]; !exists {
			log.Info("Valid cep-ceb mapping, but CEB doesn't exist in ceb cache.")
			return
		}

		ceb.backendMutex.Lock()
		defer ceb.backendMutex.Unlock()
		for i, ep := range ceb.ceb.Endpoints {
			if GetCepNameFromCCEP(&ep) == cepName {
				// Insert deleted CoreCEP in removedCeps
				ceb.removedCeps[GetCepNameFromCCEP(&ep)] = struct{}{}
				ceb.ceb.Endpoints =
					append(ceb.ceb.Endpoints[:i],
						ceb.ceb.Endpoints[i+1:]...)
				break
			}
		}
		log.WithFields(logrus.Fields{
			"ceb-name":  cebName,
			"cep-name":  cepName,
			"cep-count": len(ceb.ceb.Endpoints),
		}).Debug("Removed cep from ceb")

		c.queue.Add(cebName)
	} else {
		log.WithFields(logrus.Fields{
			"cep-name": cepName,
		}).Error("Failed to get CEB from ceptoceb map")
	}

	return
}

// Returns the total number of CEPs in the cluster
func (c *cebMgr) getTotalCepCount() int {
	cnt := 0
	for _, ceb := range c.desiredCebs {
		ceb.backendMutex.RLock()
		cnt += len(ceb.ceb.Endpoints)
		ceb.backendMutex.RUnlock()
	}
	return cnt
}

// Returns the total number of CEPs in the ceb
func (c *cebMgr) getCepCountInCeb(cebName string) (cnt int) {
	if ceb, ok := c.desiredCebs[cebName]; ok {
		ceb.backendMutex.RLock()
		cnt = len(ceb.ceb.Endpoints)
		ceb.backendMutex.RUnlock()
	}
	return
}

// Returns the total count of CEBs in local cache
func (c *cebMgr) getCebCount() int {
	return len(c.desiredCebs)
}

// Returns the list of cep names
func (c *cebMgr) getAllCepNames() []string {
	var ceps []string
	for _, ceb := range c.desiredCebs {
		ceb.backendMutex.RLock()
		for _, cep := range ceb.ceb.Endpoints {
			ceps = append(ceps, GetCepNameFromCCEP(&cep))
		}
		ceb.backendMutex.RUnlock()
	}

	return ceps
}

// Returns the list of removed Core CEPs
func (c *cebMgr) getRemovedCeps(cebName string) map[string]struct{} {
	cepNames := make(map[string]struct{})
	if ceb, _ := c.desiredCebs[cebName]; ceb != nil {
		ceb.backendMutex.RLock()
		for cepName := range ceb.removedCeps {
			cepNames[cepName] = struct{}{}
		}
		ceb.backendMutex.RUnlock()
	}

	return cepNames
}

// After successful sync with api-server, delete removed ceps in a CEB.
// If no more CEPs are packed in CEB, Delete the CEB in next DeleteSYNC.
func (c *cebMgr) clearRemovedCeps(cebName string, remCeps map[string]struct{}) {

	var ok bool
	var ceb *cebTracker
	// Check if CEB exists in local cache
	if ceb, ok = c.desiredCebs[cebName]; !ok {
		log.WithFields(logrus.Fields{
			"ceb-name": cebName,
		}).Error("Unable to find the CEB in local cache")
		return
	}

	ceb.backendMutex.Lock()
	defer ceb.backendMutex.Unlock()
	// Delete removed CEPs from caches.
	for cn := range remCeps {
		if _, ok = ceb.removedCeps[cn]; ok {
			c.cacheCepMap.deleteCep(cn)
			delete(ceb.removedCeps, cn)
		}
	}

	// If there are no CEPs are packed in CEB, mark for delete.
	if len(ceb.ceb.Endpoints) == 0 && len(ceb.removedCeps) == 0 {
		log.WithFields(logrus.Fields{
			"ceb-name": cebName,
		}).Debug("Remove CEB from local cache")
		// On next DeleteSync, Delete this CEB with api-server.
		c.queue.Add(cebName)
	}
}

// findCeb returns the available cebTracker object and is chosen based on FCFS.
// if all CEB's reached max capacity or marked for delete. Allocate a new CEB.
func (c *cebManagerIdentity) findCeb(cep *cilium_v2.CoreCiliumEndpoint) (ceb *cebTracker) {

	// get first available CEB
	log.Infof("findCeb cebIdentity called")
	if cebs, exist := c.identityToCeb[cep.IdentityID]; exist {
		for _, ceb = range cebs {
			ceb.backendMutex.RLock()
			if len(ceb.ceb.Endpoints) >= c.maxCepsInCeb || len(ceb.ceb.Endpoints) == 0 {
				ceb.backendMutex.RUnlock()
				continue
			}
			ceb.backendMutex.RUnlock()
			return
		}
	}

	// allocate a new cebTracker and return
	ceb = c.createCeb("")
	c.identityToCeb[cep.IdentityID] = append(c.identityToCeb[cep.IdentityID], ceb)
	return
}

// If exists, remove Ceb object from cache. deleteCebFromCache is called after successful removal from
// apiserver.
func (c *cebManagerIdentity) deleteCebFromCache(cebName string) {
	log.Infof("deleteceb cebIdentity called")
	if _, ok := c.desiredCebs[cebName]; !ok {
		log.WithFields(logrus.Fields{
			"ceb-name": cebName,
		}).Debug("Failed to retrieve Ceb object in local cache.")
		return
	}

	for id, cebTrackers := range c.identityToCeb {
		for i, ct := range cebTrackers {
			if ct == c.desiredCebs[cebName] {
				c.identityToCeb[id] = append(cebTrackers[:i],
					cebTrackers[i+1:]...)
				break
			}
		}
	}
	log.Infof("Delete CEB :%s", cebName)
	delete(c.desiredCebs, cebName)
}
