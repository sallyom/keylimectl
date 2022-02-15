/*
Copyright © 2022 axel simon <axel@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/spf13/cobra"
	"k8s.io/klog"
)

// verifierCmd represents the verifier command
var verifierCmd = &cobra.Command{
	Use:   "verifier",
	Short: "Check the status of a verifier",
	Run: func(cmd *cobra.Command, args []string) {
		keylimeOpts.initConfig(cmd)
		cvStatus()
	},
}

func cvStatus() {
	klog.Infof("KEYLIMEOPTS: %v", keylimeOpts)
	// Instantiate a handler for cvStatus, using config values. This might need to be scoped to the package rather than the function.
	hdl := Handler{
		//Scheme:           keylimeOpts.Config.General.TLS,
		Scheme: "http://",
		Host:   keylimeOpts.Config.Tenant.VerifierHost,
		Port:   keylimeOpts.Config.Tenant.VerifierPort,
		ApiVer: keylimeOpts.Config.ApiVer,
		Path:   "agents/?verifier=",
		//	VerifierID:
	}

	fmt.Println("Called cvStatus")

	// build cloud verifier URL
	cvURL := hdl.buildURL()
	klog.Infof("DEBUG: cvStatus(): What does hdl look like? %s", hdl)

	// GET on cvURL to get our response
	resp, err := http.Get(cvURL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Store the body of the response (which is JSON) in a body variable.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal the JSON status into a CvStatus Go struct
	var cvStatus RegStatusList
	err = json.Unmarshal(body, &cvStatus)
	if err != nil {
		log.Fatal(err)
	}
	// Print out the relevant fields of the verifier's status
	fmt.Println("Keylime cloud verifier status:")
	fmt.Println("-------")
	fmt.Println("Status:\t\t", cvStatus.Status)
	fmt.Println("Code:\t\t", cvStatus.Code)
	fmt.Println("-------")
	fmt.Println("Results:")
	for _, v := range cvStatus.Results.uuids {
		fmt.Println("UUID:\t\t", v)
	}
	fmt.Println("-------")
}
