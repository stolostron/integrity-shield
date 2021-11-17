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

package reporter

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"time"

	mid "github.com/open-cluster-management/integrity-shield/reporter/pkg/apis/manifestintegritydecision/v1"
	log "github.com/sirupsen/logrus"

	"github.com/hpcloud/tail"
	midclient "github.com/open-cluster-management/integrity-shield/reporter/pkg/client/manifestintegritydecision/clientset/versioned/typed/manifestintegritydecision/v1"
	kubeutil "github.com/open-cluster-management/integrity-shield/shield/pkg/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const defaultIntervalSecondsStr = "10"
const timeFormat = "2006-01-02T15:04:05Z"

type IntegrityShieldReporter struct {
	IShiledNamespace string
	EventsFilePath   string
	IntervalSeconds  uint64

	// loader     *Loader
	logger        *log.Logger
	DynamicClient dynamic.Interface
	MidClient     *midclient.ApisV1Client
	eventQueue    []string
}

type ConstarintEvents struct {
	Constraint string
	Events     []mid.AdmissionResult
}

func NewIntegrityShieldReporter(logger *log.Logger) *IntegrityShieldReporter {
	iShieldNS := os.Getenv("POD_NAMESPACE")
	eventsFilePath := os.Getenv("DECISION_FILE_PATH")
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
	midClient, _ := midclient.NewForConfig(config)
	return &IntegrityShieldReporter{
		IShiledNamespace: iShieldNS,
		EventsFilePath:   eventsFilePath,
		IntervalSeconds:  intervalSeconds,
		DynamicClient:    dynamicClient,
		MidClient:        midClient,
		logger:           logger,
	}
}

func (self *IntegrityShieldReporter) Run(event chan *tail.Line, report chan bool) error {
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

func (self *IntegrityShieldReporter) report(lines []string) error {

	events, err := readEventLines(lines)
	if err != nil {
		self.logger.Errorf("Failed to load events.txt; %s", err.Error())
		return err
	}
	eventsGroupedByConstraints := sortDecisionsbyConstraint(events)
	for _, constraintEvent := range eventsGroupedByConstraints {
		if constraintEvent.Constraint == "" {
			self.logger.Warning("constraint name is empty, ManifestIntegrityDecision will not be created.")
			continue
		}
		alreadyExists, currentMie := self.loadManifestIntegrityDecision(constraintEvent.Constraint)
		if alreadyExists {
			newData := self.updateDecision(currentMie.Spec, constraintEvent.Events)
			currentMie.Spec = newData
			_, err = self.MidClient.ManifestIntegrityDecisions(self.IShiledNamespace).Update(context.Background(), currentMie, metav1.UpdateOptions{})
		} else {
			newData := mid.ManifestIntegrityDecisionSpec{
				ConstraintName:   constraintEvent.Constraint,
				AdmissionResults: constraintEvent.Events,
				LastUpdate:       time.Now().Format(timeFormat),
			}
			newMie := &mid.ManifestIntegrityDecision{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constraintEvent.Constraint,
					Namespace: self.IShiledNamespace,
				},
				Spec: newData,
			}
			_, err = self.MidClient.ManifestIntegrityDecisions(self.IShiledNamespace).Create(context.Background(), newMie, metav1.CreateOptions{})
		}
		if err != nil {
			self.logger.Error("failed to update/create ManifestIntegrityDecision: ", constraintEvent.Constraint)
			return err
		}
		self.logger.Info("Updated a ManifestIntegrityDecision: ", constraintEvent.Constraint)
	}
	// remove log if resource is not exist
	self.organizeDecision()
	return nil
}

func (self *IntegrityShieldReporter) addEvent(line string) {
	self.eventQueue = append(self.eventQueue, line)
}

func (self *IntegrityShieldReporter) getEvents() []string {
	lines := []string{}
	lines = append(lines, self.eventQueue...)
	self.clearEvents()
	return lines
}

func (self *IntegrityShieldReporter) clearEvents() {
	self.eventQueue = []string{}
}

// decision
func (self *IntegrityShieldReporter) loadManifestIntegrityDecision(name string) (bool, *mid.ManifestIntegrityDecision) {
	alreadyExists := false
	currentMie, getErr := self.MidClient.ManifestIntegrityDecisions(self.IShiledNamespace).Get(context.Background(), name, metav1.GetOptions{})
	if currentMie != nil && getErr == nil {
		alreadyExists = true
		return alreadyExists, currentMie
	}
	if getErr != nil {
		self.logger.Info("failed to get manifestIntegrityDecision: ", getErr.Error())
		return alreadyExists, nil
	}
	self.logger.Info("no manifestIntegrityDecision exist: ", name)
	return alreadyExists, nil
}

func (self *IntegrityShieldReporter) updateDecision(data mid.ManifestIntegrityDecisionSpec, events []mid.AdmissionResult) mid.ManifestIntegrityDecisionSpec {
	updatedDecisions := self.updateDecisionRecord(data.AdmissionResults, events)
	data.AdmissionResults = updatedDecisions
	data.LastUpdate = time.Now().Format(timeFormat)
	return data
}

func (self *IntegrityShieldReporter) updateDecisionRecord(current, newDecisions []mid.AdmissionResult) []mid.AdmissionResult {
	for _, new := range newDecisions {
		found, i := getTargetRecord(current, new)
		if found {
			current[i] = new
		} else {
			current = append(current, new)
		}
	}
	return current
}

func (self *IntegrityShieldReporter) removeUnnecessaryDecision(decisions []mid.AdmissionResult) (bool, []mid.AdmissionResult) {
	var res []mid.AdmissionResult
	var removed bool
	for _, decision := range decisions {
		gvr := schema.GroupVersionResource{
			Group:    decision.ApiGroup,
			Version:  decision.ApiVersion,
			Resource: decision.Resource,
		}

		var err error
		if decision.Namespace != "" {
			_, err = self.DynamicClient.Resource(gvr).Namespace(decision.Namespace).Get(context.Background(), decision.Name, metav1.GetOptions{})
		} else {
			_, err = self.DynamicClient.Resource(gvr).Get(context.Background(), decision.Name, metav1.GetOptions{})
		}

		if err == nil {
			res = append(res, decision)
		} else {
			removed = true
			self.logger.Info("removed Decision log because resource does not exist:", decision)
		}
	}
	return removed, res
}

func getTargetRecord(decisions []mid.AdmissionResult, target mid.AdmissionResult) (bool, int) {
	var num int
	for i, decision := range decisions {
		if decision.ApiGroup == target.ApiGroup &&
			decision.ApiVersion == target.ApiVersion &&
			decision.Kind == target.Kind &&
			decision.Name == target.Name &&
			decision.Namespace == target.Namespace {
			return true, i
		}
	}
	return false, num
}

func readEventLines(lines []string) ([]mid.AdmissionResult, error) {
	events := []mid.AdmissionResult{}
	for _, l := range lines {
		var tmpEvent mid.AdmissionResult
		err := json.Unmarshal([]byte(l), &tmpEvent)
		if err != nil {
			continue
		}
		events = append(events, tmpEvent)
	}
	return events, nil
}

func sortDecisionsbyConstraint(events []mid.AdmissionResult) []ConstarintEvents {
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

func (self *IntegrityShieldReporter) organizeDecision() {
	mids, err := self.MidClient.ManifestIntegrityDecisions(self.IShiledNamespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		self.logger.Error(err)
		return
	}

	for _, mid := range mids.Items {
		if self.checkIfConstraintExist(mid.Name) {
			decisions := mid.Spec.AdmissionResults
			updated, new := self.removeUnnecessaryDecision(decisions)
			if updated {
				mid.Spec.LastUpdate = time.Now().Format(timeFormat)
				mid.Spec.AdmissionResults = new
				_, err = self.MidClient.ManifestIntegrityDecisions(self.IShiledNamespace).Update(context.Background(), &mid, metav1.UpdateOptions{})
				if err != nil {
					self.logger.Error(err)
					continue
				}
			}
		} else {
			err = self.MidClient.ManifestIntegrityDecisions(self.IShiledNamespace).Delete(context.Background(), mid.Name, metav1.DeleteOptions{})
			if err != nil {
				self.logger.Error(err)
				continue
			}
			self.logger.Infof("removed manifestIntegrityDecision %s because constraint is deleted", mid.Name)
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

func (self *IntegrityShieldReporter) checkIfConstraintExist(name string) bool {
	var exist bool
	gvr := schema.GroupVersionResource{
		Group:    "constraints.gatekeeper.sh",
		Version:  "v1beta1",
		Resource: "manifestintegrityconstraint",
	}
	constraintList, err := self.DynamicClient.Resource(gvr).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		self.logger.Error(err)
		return exist
	}
	for _, constraint := range constraintList.Items {
		if constraint.GetName() == name {
			exist = true
			return exist
		}
	}
	return exist
}
