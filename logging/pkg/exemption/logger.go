//
// Copyright 2021 IBM Corporation
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

package exemption

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"time"

	mie "github.com/open-cluster-management/integrity-shield/logging/pkg/apis/manifestintegrityexemption/v1"
	log "github.com/sirupsen/logrus"

	"github.com/hpcloud/tail"
	mieclient "github.com/open-cluster-management/integrity-shield/logging/pkg/client/manifestintegrityexemption/clientset/versioned/typed/manifestintegrityexemption/v1"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const defaultIntervalSecondsStr = "10"
const timeFormat = "2006-01-02 15:04:05"

type IntegrityShieldForwarder struct {
	IShiledNamespace string
	EventsFilePath   string
	IntervalSeconds  uint64

	// loader     *Loader
	logger        *log.Logger
	DynamicClient dynamic.Interface
	MieClient     *mieclient.ApisV1Client
	eventQueue    []string
}

type ConstarintEvents struct {
	Constraint string
	Events     []mie.AdmissionResult
}

func NewIntegrityShieldForwarder(logger *log.Logger) *IntegrityShieldForwarder {
	iShieldNS := os.Getenv("POD_NAMESPACE")
	eventsFilePath := os.Getenv("EVENTS_FILE_PATH")
	intervalSecondsStr := os.Getenv("INTERVAL_SECONDS")
	if intervalSecondsStr == "" {
		intervalSecondsStr = defaultIntervalSecondsStr
	}
	intervalSeconds, err := strconv.ParseUint(intervalSecondsStr, 10, 64)
	if err != nil {
		logger.Warningf("Failed to parse interval seconds `%s`; use default value: %s", intervalSecondsStr, defaultIntervalSecondsStr)
		intervalSeconds, _ = strconv.ParseUint(defaultIntervalSecondsStr, 10, 64)
	}

	config, _ := kubeutil.GetKubeConfig()

	dynamicClient, _ := dynamic.NewForConfig(config)
	mieClient, _ := mieclient.NewForConfig(config)
	return &IntegrityShieldForwarder{
		IShiledNamespace: iShieldNS,
		EventsFilePath:   eventsFilePath,
		IntervalSeconds:  intervalSeconds,
		DynamicClient:    dynamicClient,
		MieClient:        mieClient,
		logger:           logger,
	}
}

func (self *IntegrityShieldForwarder) Run(event chan *tail.Line, report chan bool) error {
	for {
		var l *tail.Line
		select {
		case l = <-event:
			self.addEvent(l.Text)
		case <-report:
			lines := self.getEvents()
			err := self.report(lines)
			if err != nil {
				return err
			}
		}
	}
}

func (self *IntegrityShieldForwarder) report(lines []string) error {

	events, err := readEventLines(lines)
	if err != nil {
		self.logger.Errorf("Failed to load events.txt; %s", err.Error())
		return err
	}
	eventsGroupedByConstraints := sortEventsbyConstraint(events)
	for _, constraintEvent := range eventsGroupedByConstraints {
		if constraintEvent.Constraint == "" {
			self.logger.Warning("constraint name is empty, ManifestIntegrityExemption will not be created.")
			continue
		}
		alreadyExists, currentMie := self.loadManifestIntegrityExemption(constraintEvent.Constraint)
		if alreadyExists {
			newData := self.updateExemption(currentMie.Spec, constraintEvent.Events)
			currentMie.Spec = newData
			_, err = self.MieClient.ManifestIntegrityExemptions(self.IShiledNamespace).Update(context.Background(), currentMie, metav1.UpdateOptions{})
		} else {
			newData := mie.ManifestIntegrityExemptionSpec{
				ConstraintName:   constraintEvent.Constraint,
				AdmissionResults: constraintEvent.Events,
				LastUpdate:       time.Now().Format(timeFormat),
			}
			newMie := &mie.ManifestIntegrityExemption{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constraintEvent.Constraint,
					Namespace: self.IShiledNamespace,
				},
				Spec: newData,
			}
			_, err = self.MieClient.ManifestIntegrityExemptions(self.IShiledNamespace).Create(context.Background(), newMie, metav1.CreateOptions{})
		}
		if err != nil {
			self.logger.Error("failed to update/create ManifestIntegrityExemption: ", constraintEvent.Constraint)
			return err
		}
		self.logger.Info("Updated a ManifestIntegrityExemption: ", constraintEvent.Constraint)
	}
	// remove log if resource is not exist
	self.organizeExemption()
	return nil
}

func (self *IntegrityShieldForwarder) addEvent(line string) {
	self.eventQueue = append(self.eventQueue, line)
}

func (self *IntegrityShieldForwarder) getEvents() []string {
	lines := []string{}
	lines = append(lines, self.eventQueue...)
	self.clearEvents()
	return lines
}

func (self *IntegrityShieldForwarder) clearEvents() {
	self.eventQueue = []string{}
}

// Exemption
func (self *IntegrityShieldForwarder) loadManifestIntegrityExemption(name string) (bool, *mie.ManifestIntegrityExemption) {
	alreadyExists := false
	currentMie, getErr := self.MieClient.ManifestIntegrityExemptions(self.IShiledNamespace).Get(context.Background(), name, metav1.GetOptions{})
	if currentMie != nil && getErr == nil {
		alreadyExists = true
		return alreadyExists, currentMie
	}
	if getErr != nil {
		self.logger.Info("failed to get manifestIntegrityExemption", getErr.Error())
		return alreadyExists, nil
	}
	self.logger.Info("no manifestIntegrityExemption exist: ", name)
	return alreadyExists, nil
}

func (self *IntegrityShieldForwarder) updateExemption(data mie.ManifestIntegrityExemptionSpec, events []mie.AdmissionResult) mie.ManifestIntegrityExemptionSpec {
	updatedExemptions := self.updateExemptionRecord(data.AdmissionResults, events)
	data.AdmissionResults = updatedExemptions
	data.LastUpdate = time.Now().Format(timeFormat)
	return data
}

func (self *IntegrityShieldForwarder) updateExemptionRecord(currentExemptions, newEvents []mie.AdmissionResult) []mie.AdmissionResult {
	for _, event := range newEvents {
		found, i := getTargetRecord(currentExemptions, event)
		if found {
			currentExemptions[i] = event
		} else {
			currentExemptions = append(currentExemptions, event)
		}
	}
	return currentExemptions
}

func (self *IntegrityShieldForwarder) removeUnnecessaryExemption(exemptions []mie.AdmissionResult) (bool, []mie.AdmissionResult) {
	var res []mie.AdmissionResult
	var removed bool
	for _, exemption := range exemptions {
		gvr := schema.GroupVersionResource{
			Group:    exemption.ApiGroup,
			Version:  exemption.ApiVersion,
			Resource: exemption.Resource,
		}

		var err error
		if exemption.Namespace != "" {
			_, err = self.DynamicClient.Resource(gvr).Namespace(exemption.Namespace).Get(context.Background(), exemption.Name, metav1.GetOptions{})
		} else {
			_, err = self.DynamicClient.Resource(gvr).Get(context.Background(), exemption.Name, metav1.GetOptions{})
		}

		if err == nil {
			res = append(res, exemption)
		} else {
			removed = true
			self.logger.Info("removed exemption log because resource does not exist:", exemption)
		}
	}
	return removed, res
}

func getTargetRecord(exemptions []mie.AdmissionResult, target mie.AdmissionResult) (bool, int) {
	var num int
	for i, exemption := range exemptions {
		if exemption.ApiGroup == target.ApiGroup &&
			exemption.ApiVersion == target.ApiVersion &&
			exemption.Kind == target.Kind &&
			exemption.Name == target.Name &&
			exemption.Namespace == target.Namespace {
			return true, i
		}
	}
	return false, num
}

func readEventLines(lines []string) ([]mie.AdmissionResult, error) {
	events := []mie.AdmissionResult{}
	for _, l := range lines {
		var tmpEvent mie.AdmissionResult
		err := json.Unmarshal([]byte(l), &tmpEvent)
		if err != nil {
			continue
		}
		events = append(events, tmpEvent)
	}
	return events, nil
}

func sortEventsbyConstraint(events []mie.AdmissionResult) []ConstarintEvents {
	var res []ConstarintEvents
	var constraints []string
	for _, event := range events {
		if !contains(constraints, event.ConstraintName) {
			constraints = append(constraints, event.ConstraintName)
		}
	}
	for _, constraint := range constraints {
		res = append(res, ConstarintEvents{Constraint: constraint})
	}

	for i, ce := range res {
		tmpEvent := ce.Events
		for _, event := range events {
			if ce.Constraint == event.ConstraintName {
				tmpEvent = append(tmpEvent, event)
			}
		}
		ce.Events = tmpEvent
		res[i] = ce
	}
	return res
}

func (self *IntegrityShieldForwarder) organizeExemption() {
	mies, err := self.MieClient.ManifestIntegrityExemptions(self.IShiledNamespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		self.logger.Error(err)
		return
	}
	for _, mie := range mies.Items {
		exemptions := mie.Spec.AdmissionResults
		updated, newExemptions := self.removeUnnecessaryExemption(exemptions)
		if updated {
			if len(newExemptions) == 0 {
				err = self.MieClient.ManifestIntegrityExemptions(self.IShiledNamespace).Delete(context.Background(), mie.Name, metav1.DeleteOptions{})
				if err != nil {
					self.logger.Error(err)
					continue
				}
				self.logger.Infof("removed manifestIntegrityExemption %s because no exmaption is included", mie.Name)
			} else {
				mie.Spec.LastUpdate = time.Now().Format(timeFormat)
				mie.Spec.AdmissionResults = newExemptions
				_, err = self.MieClient.ManifestIntegrityExemptions(self.IShiledNamespace).Update(context.Background(), &mie, metav1.UpdateOptions{})
				if err != nil {
					self.logger.Error(err)
					continue
				}
			}
		}
	}
}

func contains(s []string, e string) bool {
	for _, v := range s {
		if e == v {
			return true
		}
	}
	return false
}
