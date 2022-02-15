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

	"github.com/spf13/cobra"
	"k8s.io/klog"
)

// var so = StatusOptions from root.go
// registrarCmd represents the registrar command
var registrarCmd = &cobra.Command{
	Use:   "registrar",
	Short: "Check the status of a registrar",
	Run: func(cmd *cobra.Command, args []string) {
		keylimeOpts.initConfig(cmd)
		if keylimeOpts.uuid == "" {
			regStatus()
		} else {
			regAgentStatus()
		}
	},
}

type RegStatusList struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Results struct {
		uuids []string `json:"uuids"`
	} `json:"results"`
}

// Type RegAgentStatus is a struct to represent the JSON response sent by the registrar when querying for a given agent uuid
type RegAgentStatus struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Results struct {
		AikTpm   string `json:"aik_tpm"`
		EkTpm    string `json:"ek_tpm"`
		Ekcert   string `json:"ekcert"`
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Regcount int    `json:"regcount"`
	} `json:"results"`
}

// regStatus returns the status of a keylime registrar
func regStatus() {
	hdl := Handler{
		//Scheme:           keylimeOpts.Config.General.TLS,
		Scheme: keylimeOpts.scheme,
		Host:   keylimeOpts.Config.Tenant.RegistrarHost,
		Port:   keylimeOpts.Config.Tenant.RegistrarPort,
		ApiVer: keylimeOpts.Config.ApiVer,
		Path:   "agents",
	}
	// Workaround: Go's crypto/tls disapproves of connecting to an IP when said IP is not in the certificate's SAN.
	// if hdl.Host == "127.0.0.1" {
	// 	hdl.Host = "localhost"
	// }

	if keylimeOpts.Debug {
		klog.Infof("DEBUG: regStatus(): What does hdl look like? %s", hdl)
	}

	// Build the URL to query the registrare using the handler method buildURL
	regURL := hdl.buildURL()

	if keylimeOpts.Debug {
		fmt.Printf("DEBUG: regURL = %q of type %T\n\n", regURL, regURL)
	}

	// Use the HTTP(S) client defined in root.go on regURL to GET our response
	klog.Infof("CLIENT: %v", keylimeOpts.Client)
	resp, err := keylimeOpts.Client.Get(regURL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Store the body of the response (which is JSON) in a body variable.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal the JSON status into a RegStatusList Go struct
	var rl RegStatusList
	err = json.Unmarshal(body, &rl)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: Handle HTTP errors from the registrar
	// if rl.Status == 404 {
	// 	log.Errorf("Verifier %s on port %s does not have agent %s", hdl.Host, hdl.Port, hdl)
	// }

	// Python code:
	// if response.status_code == 404:
	// logger.info("Verifier at %s with Port %s does not have agent %s.",
	// 			self.verifier_ip, self.verifier_port, self.agent_uuid)
	// return response.json()

	// Print out the relevant fields of the registrar's status
	fmt.Println("Keylime registrar status:")
	fmt.Println("-------")
	fmt.Println("Status:\t\t", rl.Status)
	fmt.Println("Code:\t\t", rl.Code)
	fmt.Println("-------")
	fmt.Println("Results:")
	for _, v := range rl.Results.uuids {
		fmt.Println("Agent uuid:\t\t", v)
	}
	fmt.Println("-------\n")
}

// regAgentStatus returns the status of a keylime agent registered with a registrar
func regAgentStatus() {
	// Instantiate a handler for regAgentStatus, using config values.
	hdl := Handler{
		//Scheme:           keylimeOpts.Config.General.TLS,
		Scheme: keylimeOpts.scheme,
		Host:   keylimeOpts.Config.Tenant.RegistrarHost,
		Port:   keylimeOpts.Config.Tenant.RegistrarPort,
		ApiVer: keylimeOpts.Config.ApiVer,
		Path:   "agents",
	}

	// Add agent uuid to the path
	hdl.Path += "/" + keylimeOpts.uuid

	// Build query URL
	regURL := hdl.buildURL()

	fmt.Printf("DEBUG: regURL = %q of type %T\n\n", regURL, regURL)

	// GET on regURL to get our response
	resp, err := keylimeOpts.Client.Get(regURL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Store the body of the response (which is JSON) in a body variable.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal the JSON status into a RegAgentStatus Go struct
	var ra RegAgentStatus
	err = json.Unmarshal(body, &ra)
	if err != nil {
		log.Fatal(err)
	}

	if ra.Code != 200 {
		log.Fatalf("Error: agent \"%s\" doesn't exist on the registrar.\nPlease register the agent on the registrar and try again.\n", keylimeOpts.uuid)
	} else {
		// Print out the relevant fields of the registrar's agent status
		fmt.Println("Keylime registrar registered agent status:")
		fmt.Println("-------")
		fmt.Println("Status:\t\t", ra.Status)
		fmt.Println("Code:\t\t", ra.Code)
		fmt.Println("-------")
		fmt.Println("Results:")
		fmt.Println("TPM AIK:\t\t", ra.Results.AikTpm)
		fmt.Println("TPM EK:\t\t", ra.Results.EkTpm)
		fmt.Println("TPM EK Cert:\t\t", ra.Results.Ekcert)
		fmt.Println("Agent host:\t\t", ra.Results.IP)
		fmt.Println("Agent port:\t\t", ra.Results.Port)
		fmt.Println("Agent reg count:\t\t", ra.Results.Regcount)
		fmt.Println("-------\n")
	}
}
