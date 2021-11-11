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

package main

import (
	"github.com/hpcloud/tail"
	"github.com/jasonlvhit/gocron"
	elogger "github.com/open-cluster-management/integrity-shield/logging/pkg/exemption"

	log "github.com/sirupsen/logrus"
)

var logger *log.Logger

func init() {
	logger = log.StandardLogger()
	logger.SetFormatter(&log.JSONFormatter{})
}

func main() {

	logger.Info("Logger container has started.")

	reportChannel := make(chan bool)

	iShieldForwarder := elogger.NewIntegrityShieldForwarder(logger)
	interval := iShieldForwarder.IntervalSeconds
	fpath := iShieldForwarder.EventsFilePath

	tailConf := tail.Config{
		ReOpen: true, // "true" enables to reopen a recreated file (tail -F)
		Follow: true, // "true" enables following a file (tail -f), this must be also set if ReOpen is true
		Poll:   true, // "true" uses poll instead of inotify, this must be set when the file is recreated on the rotation
		Logger: logger,
	}

	// tail events.txt
	t, err := tail.TailFile(fpath, tailConf)
	if err != nil {
		log.Errorf("Failed to start tailing %s; %s", fpath, err.Error())
		return
	}
	// event signal is sent when new line is added
	eventChannel := t.Lines

	// set gocron job to trigger reporting
	gocron.Every(interval).Second().Do(func() {
		reportChannel <- true
	})

	// start gocron goroutine for periodical reporting
	go func() {
		<-gocron.Start()
	}()

	// start observer loop in main thread
	err = iShieldForwarder.Run(eventChannel, reportChannel)
	if err != nil {
		logger.Errorf("Error occured while running observer; %s", err.Error())
		return
	}
}
