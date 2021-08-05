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

package ciliumendpointslice

import (
	"fmt"
	"math/rand"
	"time"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
)

var (
	// sequentialLetters contains lower case alphabets without vowels and few numbers.
	// skipped vowels and numbers [0, 1] to avoid generating controversial names.
	sequentialLetters = []rune("bcdfghjklmnpqrstvwxyz2456789")
)

// cesTracker holds the desired state of CiliumEndpointSlice and list of ceps to be removed
// in next sync with k8s-apiserver.
type cesTracker struct {
	// Mutex to protect cep insert/removal in ces and removedCEPs
	backendMutex lock.RWMutex
	// The desired state of ces object
	ces *cilium_v2.CiliumEndpointSlice
	// set of CEPs to be removed in the CES object in next sync.
	removedCEPs map[string]struct{}
	// number of CEPs inserted in a CES
	cepInserted int64
	// number of CEPs removed from a CES
	cepRemoved int64
	// CES insert time at workqueue
	cesInsertedAt time.Time
}

// cesManager
type cesManager interface {
	// External APIs to Insert/Remove CEP in local dataStore
	InsertCepInCache(cep *cilium_v2.CoreCiliumEndpoint, ns string) string
	RemoveCepFromCache(cepName string)
	// Supporting APIs to Insert/Remove CEP in local dataStore and effectively
	// manages CES's.
	getCESFromCache(cesName string) (*cilium_v2.CiliumEndpointSlice, error)
	getCESCopyFromCache(cesName string) (*cilium_v2.CiliumEndpointSlice, error)
	updateCESInCache(ces *cilium_v2.CiliumEndpointSlice, deepCopy bool)
	deleteCESFromCache(cesName string)
	getRemovedCEPs(string) map[string]struct{}
	clearRemovedCEPs(string, map[string]struct{})
	createCES(cesName string) *cesTracker
	addCEPtoCES(ces *cilium_v2.CoreCiliumEndpoint, cesName string)
	insertCESInWorkQueue(ces *cesTracker)
	// APIs to collect metrics of CES and CEP
	getTotalCepCount() int
	getCepCountInCES(cesName string) int
	getCESCount() int
	getAllCepNames() []string
	getCESMetricCountersAndClear(cesName string) (cepInsert int64, cepRemove int64)
	getCESQueueDelayInSeconds(cesName string) (diff float64)
}

// cesMgr is used to batch CEP into a CES, based on FirstComeFirstServe. If a new CEP
// is inserted, then the CEP is queued in any one of the available CES. CEPs are
// inserted into CESs without any preference or any priority.
type cesMgr struct {

	// desiredCESs is used to map CESName to CESTracker[i.e. list of CEPs],
	// as well as CEPName to CESName.
	desiredCESs *CESToCEPMapping

	// workqueue is used to sync CESs with the api-server. this will rate-limit the
	// CES requests going to api-server, ensures a single CES will not be proccessed
	// multiple times concurrently, and if CES is added multiple times before it
	// can be processed, this will only be processed only once.
	queue workqueue.RateLimitingInterface

	// maxCEPsInCES is the maximum number of CiliumCoreEndpoint(s) packed in
	// a CiliumEndpointSlice Resource.
	maxCEPsInCES int
}

// cesManagerFcfs use cesMgr by design, it inherits all the methods from the base cesMgr and there is no
// special handling required for FCFS.
type cesManagerFcfs struct {
	cesMgr
}

// cesManagerIdentity is used to batch CEPs in CES based on CEP identity.
type cesManagerIdentity struct {
	cesMgr
	// Mutex to protect cep insert/removal in ces and removedCEPs
	identityLock lock.RWMutex
	// CEP identity to cesTracker map
	identityToCES map[int64][]*cesTracker
	// reverse map of identityToCES i.e. cesName to CEP identity
	cesToIdentity map[string]int64
}

// newCESManagerFcfs creates and initializes a new FCFS based manager.
func newCESManagerFcfs(workQueue workqueue.RateLimitingInterface, maxCEPsInCES int) cesManager {
	return &cesManagerFcfs{
		cesMgr{
			desiredCESs:  newDesiredCESMap(),
			queue:        workQueue,
			maxCEPsInCES: maxCEPsInCES,
		},
	}
}

// newCESManagerIdentity creates and initializes a new Identity based manager.
func newCESManagerIdentity(workQueue workqueue.RateLimitingInterface, maxCEPsInCES int) cesManager {

	c := cesMgr{
		desiredCESs:  newDesiredCESMap(),
		queue:        workQueue,
		maxCEPsInCES: maxCEPsInCES,
	}
	return &cesManagerIdentity{
		cesMgr:        c,
		identityToCES: make(map[int64][]*cesTracker),
		cesToIdentity: make(map[string]int64),
	}
}

// addCEPtoCES inserts the CEP in a CES, if the CEP already exists in a CES
// it replaces with new CEP.
func (c *cesMgr) addCEPtoCES(cep *cilium_v2.CoreCiliumEndpoint, cesName string) {

	ces := c.desiredCESs.getCESTrackerOnly(cesName)
	ces.backendMutex.Lock()
	defer ces.backendMutex.Unlock()
	// If cep already exists in ces, compare new cep with cached cep.
	// Update only if there is any change.
	log.WithFields(logrus.Fields{
		"CEPName":        cep.Name,
		"CESName":        ces.ces.GetName(),
		"total CEPCount": len(ces.ces.Endpoints),
	}).Debug("Queueing CEP in the CES")

	for i, ep := range ces.ces.Endpoints {
		if GetCepNameFromCCEP(&ep, ces.ces.Namespace) == GetCepNameFromCCEP(cep, ces.ces.Namespace) {
			if cep.DeepEqual(&ep) {
				return
			}
			// Remove the matched cep from ces endpoints list.
			ces.ces.Endpoints =
				append(ces.ces.Endpoints[:i], ces.ces.Endpoints[i+1:]...)
			break
		}
	}

	// Insert the cep in ces endpoints list.
	ces.ces.Endpoints = append(ces.ces.Endpoints, *cep)
	// If this CEP is re-generated again before previous CEP-DELETE completed.
	// remove this from removedCep list.
	if _, ok := ces.removedCEPs[GetCepNameFromCCEP(cep, ces.ces.Namespace)]; ok {
		delete(ces.removedCEPs, GetCepNameFromCCEP(cep, ces.ces.Namespace))
	}
	// Increment the cepInsert counter
	ces.cepInserted += 1
	c.insertCESInWorkQueue(ces)
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

// Generates unique random name for the CiliumEndpointSlice, the format
// of a CES name is similar to pod k8s naming convention "ces-123456789-abcde".
// First 3 letters indicates ces resource, followed by random letters.
func uniqueCESliceName(desiredCESs *CESToCEPMapping) string {
	rand.Seed(time.Now().UnixNano())
	var cesName string
	for {
		cesName = fmt.Sprintf("%s-%s-%s", cesNamePrefix, randomName(9), randomName(5))
		if !desiredCESs.hasCESName(cesName) {
			return cesName
		}
	}
}

// This function create a new ces and capacity to hold maximum ceps in a CES.
//  called on 2 different scenarios.
// 1) During runtime, when ces manager decides to create a new ces, it calls
//    with an empty name, it generates a random unique name and assign it to the CES.
// 2) During operator warm boot [after crash or software upgrade], slicing manager
//    creates a CES, by passing unique name.
func (c *cesMgr) createCES(name string) *cesTracker {
	var cesName string = name
	if name == "" {
		cesName = uniqueCESliceName(c.desiredCESs)
	}
	ces := &cesTracker{
		ces: &cilium_v2.CiliumEndpointSlice{
			TypeMeta: meta_v1.TypeMeta{
				Kind:       "CiliumEndpointSlice",
				APIVersion: cilium_v2.SchemeGroupVersion.String(),
			},
			ObjectMeta: meta_v1.ObjectMeta{
				Name: cesName,
			},
			Endpoints: make([]cilium_v2.CoreCiliumEndpoint, 0, c.maxCEPsInCES),
		},
		removedCEPs: make(map[string]struct{}),
	}
	c.desiredCESs.insertCES(cesName, ces)
	log.WithFields(logrus.Fields{
		"CESName": cesName,
	}).Debug("Generated CES")
	return ces
}

// If exists, remove CES object from cache. deleteCESFromCache is called after successful removal from
// apiserver.
func (c *cesMgr) deleteCESFromCache(cesName string) {
	if !c.desiredCESs.hasCESName(cesName) {
		log.WithFields(logrus.Fields{
			"CESName": cesName,
		}).Debug("Failed to retrieve CES object in local cache.")
		return
	}
	c.desiredCESs.deleteCES(cesName)
}

// updateCESInCache function copies the ciliumEndpoint object in local cache. if isDeepCopy flag is set,
// whole CoreCiliumEndpoint object stored in local cache.
// There are two scenarios updateCESInCache is called.
// 1) During operator warm boot[after crash or software upgrade], CES controller sync CES states from
// api-server to cache. In this case, isDeepCopy set to true to copy entire CEP object locally.
// 2) During runtime, reconciler sync current state with API server and update metadata only.
// isDeepCopy flag is set to false.
func (c *cesMgr) updateCESInCache(srcCES *cilium_v2.CiliumEndpointSlice, isDeepCopy bool) {
	if ces, ok := c.desiredCESs.getCESTracker(srcCES.GetName()); ok {
		ces.backendMutex.Lock()
		defer ces.backendMutex.Unlock()
		if !isDeepCopy {
			ces.ces.ObjectMeta = srcCES.ObjectMeta
		} else {
			ces.ces = srcCES
			for _, cep := range ces.ces.Endpoints {
				// Update the desiredCESs, to reflect all CEPs are packed in a CES
				c.desiredCESs.insertCEP(GetCepNameFromCCEP(&cep, ces.ces.Namespace), srcCES.GetName())
			}
		}
	}
}

// If available, getCESFromCache returns CiliumEndpointSlice object.
func (c *cesMgr) getCESFromCache(cesName string) (*cilium_v2.CiliumEndpointSlice, error) {
	if ces, exists := c.desiredCESs.getCESTracker(cesName); exists {
		return ces.ces, nil
	}
	return nil, fmt.Errorf("Failed to get CES from local cache for the CESName: %s", cesName)
}

// getCESCopyFromCache returns the copy of CiliumEndpointSlice object.
func (c *cesMgr) getCESCopyFromCache(cesName string) (*cilium_v2.CiliumEndpointSlice, error) {
	if ces, exists := c.desiredCESs.getCESTracker(cesName); exists {
		outCES := new(cilium_v2.CiliumEndpointSlice)
		ces.backendMutex.RLock()
		ces.ces.DeepCopyInto(outCES)
		ces.backendMutex.RUnlock()
		return outCES, nil

	}
	return nil, fmt.Errorf("Failed to get CES Copy from local cache for the CESName: %s", cesName)
}

// InsertCepInCache is used to insert CEP in local cache, this may result in creating a new
// CES object or updating an existing CES object.
func (c *cesMgr) InsertCepInCache(cep *cilium_v2.CoreCiliumEndpoint, ns string) string {

	log.WithFields(logrus.Fields{
		"CEPName": GetCepNameFromCCEP(cep, ns),
	}).Debug("Insert CEP in local cache")

	// check the given cep is already exists in any of the CES.
	// if yes, Update a ces with the given cep object.
	if cesName, exists := c.desiredCESs.getCESName(GetCepNameFromCCEP(cep, ns)); exists {
		// add a cep into the ces
		c.addCEPtoCES(cep, cesName)
		return cesName
	}

	// If given cep object isn't packed in any of the CES. find a new ces
	// to pack this cep.
	cb := func() *cesTracker {
		// get first available CES
		for _, ces := range c.desiredCESs.getAllCESs() {
			ces.backendMutex.RLock()
			if ces.ces.Namespace != ns || len(ces.ces.Endpoints) >= c.maxCEPsInCES || len(ces.ces.Endpoints) == 0 {
				ces.backendMutex.RUnlock()
				continue
			}
			ces.backendMutex.RUnlock()
			return ces
		}
		// allocate a new cesTracker and return
		newCES := c.createCES("")
		// Update the namespace to CES
		newCES.ces.Namespace = ns
		return newCES
	}()

	// Cache CEP name with newly allocated CES.
	c.desiredCESs.insertCEP(GetCepNameFromCCEP(cep, ns), cb.ces.GetName())

	// Queue the CEP in CES
	c.addCEPtoCES(cep, cb.ces.GetName())
	return cb.ces.GetName()
}

// RemoveCepFromCache is used to remove the CEP from local cache, this may result in
// Updating an existing CES object.
func (c *cesMgr) RemoveCepFromCache(cepName string) {

	log.WithFields(logrus.Fields{
		"CEPName": cepName,
	}).Debug("Remove CEP from local cache")

	// Check in local cache, if a given cep is already batched in one of the ces.
	// and if exists, delete cep from ces.
	if cesName, exists := c.desiredCESs.getCESName(cepName); exists {
		var ces *cesTracker
		if ces, exists = c.desiredCESs.getCESTracker(cesName); !exists {
			log.Info("Valid CEP-CES mapping, but CES doesn't exist in CES cache.")
			return
		}

		ces.backendMutex.Lock()
		defer ces.backendMutex.Unlock()
		for i, ep := range ces.ces.Endpoints {
			if GetCepNameFromCCEP(&ep, ces.ces.Namespace) == cepName {
				// Insert deleted CoreCEP in removedCEPs
				ces.removedCEPs[GetCepNameFromCCEP(&ep, ces.ces.Namespace)] = struct{}{}
				ces.ces.Endpoints =
					append(ces.ces.Endpoints[:i],
						ces.ces.Endpoints[i+1:]...)
				break
			}
		}
		log.WithFields(logrus.Fields{
			"CESName":  cesName,
			"CEPName":  cepName,
			"CEPCount": len(ces.ces.Endpoints),
		}).Debug("Removed CEP from CES")

		// Increment the cepRemove counter
		ces.cepRemoved += 1
		c.insertCESInWorkQueue(ces)
	} else {
		log.WithFields(logrus.Fields{
			"CEPName": cepName,
		}).Error("Failed to get CES from CESToCEPMapping")
	}

	return
}

// Returns the total number of CEPs in the cluster
func (c *cesMgr) getTotalCepCount() int {
	cnt := 0
	for _, ces := range c.desiredCESs.getAllCESs() {
		ces.backendMutex.RLock()
		cnt += len(ces.ces.Endpoints)
		ces.backendMutex.RUnlock()
	}
	return cnt
}

// Returns the total number of CEPs in the ces
func (c *cesMgr) getCepCountInCES(cesName string) (cnt int) {
	if ces, ok := c.desiredCESs.getCESTracker(cesName); ok {
		ces.backendMutex.RLock()
		cnt = len(ces.ces.Endpoints)
		ces.backendMutex.RUnlock()
	}
	return
}

// Returns the total count of CESs in local cache
func (c *cesMgr) getCESCount() int {
	return (c.desiredCESs.getCESCount())
}

// Returns the list of cep names
func (c *cesMgr) getAllCepNames() []string {
	var ceps []string
	for _, ces := range c.desiredCESs.getAllCESs() {
		ces.backendMutex.RLock()
		for _, cep := range ces.ces.Endpoints {
			ceps = append(ceps, GetCepNameFromCCEP(&cep, ces.ces.Namespace))
		}
		ces.backendMutex.RUnlock()
	}

	return ceps
}

// Returns the list of removed Core CEPs
func (c *cesMgr) getRemovedCEPs(cesName string) map[string]struct{} {
	cepNames := make(map[string]struct{})
	if ces := c.desiredCESs.getCESTrackerOnly(cesName); ces != nil {
		ces.backendMutex.RLock()
		for cepName := range ces.removedCEPs {
			cepNames[cepName] = struct{}{}
		}
		ces.backendMutex.RUnlock()
	}

	return cepNames
}

// After successful sync with api-server, delete removed ceps in a CES.
// If no more CEPs are packed in CES, Delete the CES in next DeleteSYNC.
func (c *cesMgr) clearRemovedCEPs(cesName string, remCEPs map[string]struct{}) {

	var ok bool
	var ces *cesTracker
	// Check if CES exists in local cache
	if ces, ok = c.desiredCESs.getCESTracker(cesName); !ok {
		log.WithFields(logrus.Fields{
			"CESName": cesName,
		}).Error("Unable to find the CES in local cache")
		return
	}

	ces.backendMutex.Lock()
	defer ces.backendMutex.Unlock()
	// Delete removed CEPs from caches.
	for cn := range remCEPs {
		if _, ok = ces.removedCEPs[cn]; ok {
			c.desiredCESs.deleteCEP(cn)
			delete(ces.removedCEPs, cn)
		}
	}

	// If there are no CEPs are packed in CES, mark for delete.
	if len(ces.ces.Endpoints) == 0 && len(ces.removedCEPs) == 0 {
		log.WithFields(logrus.Fields{
			"CESName": cesName,
		}).Debug("Remove CES from local cache")
		// On next DeleteSync, Delete this CES with api-server.
		c.insertCESInWorkQueue(ces)
	}
}

func (c *cesMgr) getCESMetricCountersAndClear(cesName string) (cepInsert int64, cepRemove int64) {
	if ces, exists := c.desiredCESs.getCESTracker(cesName); exists {
		ces.backendMutex.Lock()
		defer ces.backendMutex.Unlock()
		cepInsert = ces.cepInserted
		cepRemove = ces.cepRemoved
		ces.cepInserted = 0
		ces.cepRemoved = 0
	}

	return
}

// If exists, remove CES object from cache. deleteCESFromCache is called after successful removal from
// apiserver.
func (c *cesManagerIdentity) deleteCESFromCache(cesName string) {
	if !c.desiredCESs.hasCESName(cesName) {
		log.WithFields(logrus.Fields{
			"CESName": cesName,
		}).Debug("Failed to retrieve CES object in local cache.")
		return
	}

	c.identityLock.Lock()
	identity, _ := c.cesToIdentity[cesName]
	for i, ces := range c.identityToCES[identity] {
		if cesName == ces.ces.GetName() {
			c.identityToCES[identity] = append(c.identityToCES[identity][:i],
				c.identityToCES[identity][i+1:]...)

			if len(c.identityToCES[identity]) == 0 {
				delete(c.identityToCES, identity)
			}
			break
		}
	}
	delete(c.cesToIdentity, cesName)
	c.identityLock.Unlock()
	c.desiredCESs.deleteCES(cesName)
}

// InsertCepInCache is used to insert CEP in local cache, this may result in creating a new
// CES object or updating an existing CES object. CEPs are grouped based on CEP identity.
func (c *cesManagerIdentity) InsertCepInCache(cep *cilium_v2.CoreCiliumEndpoint, ns string) string {

	// check the given cep is already exists in any of the CES.
	// if yes, Update a ces with the given cep object.
	if cesName, exists := c.desiredCESs.getCESName(GetCepNameFromCCEP(cep, ns)); exists {
		// add a cep into the ces
		c.addCEPtoCES(cep, cesName)
		return cesName
	}

	// If given cep object isn't packed in any of the CES. find a new ces
	// to pack this cep.
	cb := func() *cesTracker {
		// get first available CES
		if cess, exist := c.identityToCES[cep.IdentityID]; exist {
			for _, ces := range cess {
				ces.backendMutex.RLock()
				if len(ces.ces.Endpoints) >= c.maxCEPsInCES || len(ces.ces.Endpoints) == 0 {
					ces.backendMutex.RUnlock()
					continue
				}
				ces.backendMutex.RUnlock()
				return ces
			}
		}
		// allocate a new cesTracker and return
		ces := c.createCES("")
		// Update the namespace to CES
		ces.ces.Namespace = ns

		// Update the identityToCES and cesToIdentity maps respectively.
		c.identityLock.Lock()
		c.identityToCES[cep.IdentityID] = append(c.identityToCES[cep.IdentityID], ces)
		c.cesToIdentity[ces.ces.GetName()] = cep.IdentityID
		c.identityLock.Unlock()

		return ces
	}()

	// Cache CEP name with newly allocated CES.
	c.desiredCESs.insertCEP(GetCepNameFromCCEP(cep, ns), cb.ces.GetName())

	// Queue the CEP in CES
	c.addCEPtoCES(cep, cb.ces.GetName())
	return cb.ces.GetName()
}

// updateCESInCache function copies the ciliumEndpoint object in local cache. if isDeepCopy flag is set,
// whole CoreCiliumEndpoint object stored in local cache.
// There are two scenarios updateCESInCache is called.
// 1) During operator warm boot[after crash or software upgrade], CES controller sync CES states from
// api-server to cache. In this case, isDeepCopy set to true to copy entire CEP object locally.
// 2) During runtime, reconciler sync current state with API server and update metadata only.
// isDeepCopy flag is set to false.
func (c *cesManagerIdentity) updateCESInCache(srcCES *cilium_v2.CiliumEndpointSlice, isDeepCopy bool) {
	if ces, ok := c.desiredCESs.getCESTracker(srcCES.GetName()); ok {
		ces.backendMutex.Lock()
		defer ces.backendMutex.Unlock()
		if !isDeepCopy {
			ces.ces.ObjectMeta = srcCES.ObjectMeta
		} else {
			ces.ces = srcCES
			_, exist := c.cesToIdentity[srcCES.GetName()]
			for _, cep := range ces.ces.Endpoints {
				// Update the identityToCES and cesToIdentity maps respectively.
				if !exist {
					c.identityLock.Lock()
					c.identityToCES[cep.IdentityID] = append(c.identityToCES[cep.IdentityID], ces)
					c.cesToIdentity[srcCES.GetName()] = cep.IdentityID
					c.identityLock.Unlock()
					exist = true
				}
				// Update the desiredCESs, to reflect all CEPs are packed in a CES
				c.desiredCESs.insertCEP(GetCepNameFromCCEP(&cep, ces.ces.Namespace), srcCES.GetName())
			}
		}
	}
}

// Insert the ces in workqueue
func (c *cesMgr) insertCESInWorkQueue(ces *cesTracker) {
	// If CES insert time is not zero, save current time.
	if ces.cesInsertedAt.IsZero() {
		ces.cesInsertedAt = time.Now()
	}
	c.queue.Add(ces.ces.GetName())
}

// Return the CES queue delay in seconds and reset cesInsert time.
func (c *cesMgr) getCESQueueDelayInSeconds(cesName string) (diff float64) {
	ces := c.desiredCESs.getCESTrackerOnly(cesName)
	ces.backendMutex.Lock()
	defer ces.backendMutex.Unlock()
	timeSinceCESQueued := time.Since(ces.cesInsertedAt)
	if !ces.cesInsertedAt.IsZero() {
		var t time.Time
		// Reset the cesInsertedAt value
		ces.cesInsertedAt = t
		diff = timeSinceCESQueued.Seconds()
	}
	return
}