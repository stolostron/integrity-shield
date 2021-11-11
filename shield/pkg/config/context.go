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

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

// NOTE: this singleton logger should be used only for simple log messages
// for detail logs while handling a certain request, Handler.requestLog should be used instead.
var simpleLogger *log.Logger
var (
	defaultFilePath   = "/ishield-app/public/events.txt"
	defaultRotateSize = int64(10485760) // 10MB
)

type ContextLoggerConfig struct {
	Enabled   bool
	File      string
	LimitSize int64
}

type ContextLogger struct {
	enabled   bool
	file      string
	limitSize int64
}

func init() {
	simpleLogger = log.New()
	simpleLogger.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})
}

func InitContextLogger(config LogConfig) *ContextLogger {
	file := os.Getenv("EVENTS_FILE_PATH")
	limit := config.ContextLoggerLimitSize
	if file == "" {
		file = defaultFilePath
	}
	if limit == 0 {
		limit = defaultRotateSize
	}
	contextLogger := &ContextLogger{
		enabled:   config.ContextLoggerEnabled,
		file:      file,
		limitSize: limit,
	}
	return contextLogger
}

func (cxLogger *ContextLogger) sizeCheckAndRotate() error {
	f, err := os.OpenFile(cxLogger.file, os.O_CREATE|os.O_WRONLY, 0640) // NOSONAR
	if err != nil {
		simpleLogger.WithFields(log.Fields{
			"err": err,
		}).Debug("failed to open file")

		return err
	}
	defer func() {
		_ = f.Close()
	}()

	fi, err := f.Stat()
	if err != nil {
		simpleLogger.WithFields(log.Fields{
			"err": err,
		}).Debug("failed to open file")
		return err
	}
	if fi.Size() > cxLogger.limitSize {
		err := os.Remove(cxLogger.file)
		if err != nil {
			simpleLogger.WithFields(log.Fields{
				"err": err,
			}).Debug("failed to remove file")
			return err
		}
	}
	return nil
}

func (cxLogger *ContextLogger) writeToFile(logBytes []byte) error {
	err := cxLogger.sizeCheckAndRotate()
	if err != nil {
		simpleLogger.WithFields(log.Fields{
			"err": err,
		}).Debug("err from sizeCheckAndRotate")
		return err
	}

	f, err := os.OpenFile(cxLogger.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640) // NOSONAR
	if err != nil {
		simpleLogger.WithFields(log.Fields{
			"err": err,
		}).Debug("failed to open file")
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	line := fmt.Sprintf("%s\n", string(logBytes))
	if _, err := f.WriteString(line); err != nil {
		simpleLogger.WithFields(log.Fields{
			"err": err,
		}).Debug("failed to write string")
		return err
	}
	return nil
}

func (cxLogger *ContextLogger) SendLog(logRecord map[string]interface{}) {
	if !cxLogger.enabled {
		return
	}
	logBytes, err := json.Marshal(logRecord)
	if err != nil {
		log.Warning("failed to marshal log:", err.Error())
		logBytes = []byte("")
	}

	err = cxLogger.writeToFile(logBytes)
	if err != nil {
		simpleLogger.WithFields(log.Fields{
			"err": err,
		}).Debug("Context log file dump err")
		return
	}

}
