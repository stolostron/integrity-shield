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

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	k8smnfconfig "github.com/open-cluster-management/integrity-shield/shield/pkg/config"
	"github.com/open-cluster-management/integrity-shield/shield/pkg/shield"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	tlsDir      = `/run/secrets/tls`
	tlsCertFile = `tls.crt`
	tlsKeyFile  = `tls.key`
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.Info("Integrity Shield has been started.")
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	errorHandler(w, r, http.StatusNotFound)
}

func errorHandler(w http.ResponseWriter, r *http.Request, status int) {
	w.WriteHeader(status)
	if status == http.StatusNotFound {
		fmt.Fprint(w, "Custom 404")
	}
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	log.Info("request received")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	bufbody := new(bytes.Buffer)
	_, _ = bufbody.ReadFrom(r.Body)
	body := bufbody.Bytes()
	var inputMap map[string]interface{}
	var request *admission.Request
	var parameters *k8smnfconfig.ParameterObject
	err := json.Unmarshal(body, &inputMap)
	if err != nil {
		http.Error(w, fmt.Sprintf("unmarshaling input data as map[string]interface{}: %v", err), http.StatusInternalServerError)
		return
	}

	requestIf, requestFound := inputMap["request"]
	if !requestFound {
		http.Error(w, "failed to find `request` key in input object", http.StatusInternalServerError)
		return
	}
	if requestIf != nil {
		requestMap := requestIf.(map[string]interface{})
		requestBytes, _ := json.Marshal(requestMap)
		_ = json.Unmarshal(requestBytes, &request)
	}
	if request == nil {
		http.Error(w, fmt.Sprintf("failed to convert `request` in input object into %T", request), http.StatusInternalServerError)
		return
	}
	log.Infof("request has been parsed successfully, kind: %s, name: %s", request.Kind.Kind, request.Name)

	parametersIf, parametersFound := inputMap["parameters"]
	if !parametersFound {
		http.Error(w, "failed to find `parameters` key in input object", http.StatusInternalServerError)
		return
	}
	if parametersIf != nil {
		parametersMap := parametersIf.(map[string]interface{})
		parametersBytes, _ := json.Marshal(parametersMap)
		_ = json.Unmarshal(parametersBytes, &parameters)
	}
	if parameters == nil {
		http.Error(w, fmt.Sprintf("failed to convert `parameters` in input object into %T", parameters), http.StatusInternalServerError)
		return
	}

	result := shield.RequestHandler(*request, parameters)
	resp, err := json.Marshal(result)
	if err != nil {
		http.Error(w, fmt.Sprintf("marshaling request handler result: %v", err), http.StatusInternalServerError)
		return
	}

	log.Infof("returning a response, allow: %v", result.Allow)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(resp); err != nil {
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
		return
	}
}

func checkLiveness(w http.ResponseWriter, r *http.Request) {
	msg := "liveness ok"
	_, _ = w.Write([]byte(msg))
}

func checkReadiness(w http.ResponseWriter, r *http.Request) {
	msg := "readiness ok"
	_, _ = w.Write([]byte(msg))
}

func main() {
	tlsCertPath := path.Join(tlsDir, tlsCertFile)
	tlsKeyPath := path.Join(tlsDir, tlsKeyFile)

	pair, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)

	if err != nil {
		panic(fmt.Sprintf("unable to load certs: %v", err))
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api", defaultHandler)
	mux.HandleFunc("/api/request", requestHandler)
	mux.HandleFunc("/health/liveness", checkLiveness)
	mux.HandleFunc("/health/readiness", checkReadiness)

	serverObj := &http.Server{
		Addr:      ":8080",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		Handler:   mux,
	}

	if err := serverObj.ListenAndServeTLS("", ""); err != nil {
		panic(fmt.Sprintf("Fail to run integrity shield api: %v", err))
	}
}
