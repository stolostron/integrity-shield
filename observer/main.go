// Copyright 2021  IBM Corporation
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

package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/open-cluster-management/integrity-shield/observer/pkg/observer"
)

func main() {
	insp := observer.NewObserver()
	err := insp.Init()
	if err != nil {
		fmt.Println("Failed to initialize Observer; err: ", err.Error())
		return
	}
	intervalInt, _ := strconv.Atoi(os.Getenv("INTERVAL"))
	fmt.Println("observer started.")
	insp.Run()
	abort := make(chan struct{})
	ticker := time.NewTicker(time.Duration(intervalInt) * time.Minute)
	for {
		select {
		case <-ticker.C:
			insp.Run()

		case <-abort:
			fmt.Println("Launch aborted!")
			return
		}
	}

}
