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

// TODO: clean this up. This (agent UUID) variable's scope is questionable.
var (
	uuid   string
	scheme = "https://"
)

// func setTLS() {
// 	if C.General.TLS {
// 		var scheme = "https://"
// 	} else {
// 		var scheme = "http://"
// 	}
// }

// registrarCmd represents the registrar command
var registrarCmd = &cobra.Command{
	Use:   "registrar",
	Short: "Check the status of a registrar",
	Run: func(cmd *cobra.Command, args []string) {
		if uuid == "" {
			regStatus()
		} else {
			regAgentStatus(uuid)
		}
	},
}

// regStatus returns the status of a keylime registrar
func regStatus() {
	// Build a handler for a subset of our config (taken from Shiori)
	// This should be reusable for cvlist, cvstatus, etc.

	// Instantiate a handler for regStatus, using config values. This might need to be scoped to the package rather than the function.
	hdl := Handler{
		//Scheme:           C.General.TLS,
		Scheme: scheme,
		Host:   C.Tenant.RegistrarHost,
		Port:   C.Tenant.RegistrarPort,
		ApiVer: C.ApiVer,
		Path:   "agents",
	}
	// Workaround: Go's crypto/tls disapproves of connecting to an IP when said IP is not in the certificate's SAN.
	// if hdl.Host == "127.0.0.1" {
	// 	hdl.Host = "localhost"
	// }

	if Debug {
		klog.Infof("DEBUG: regStatus(): What does hdl look like? %s", hdl)
	}

	// Build the URL to query the registrare using the handler method buildURL
	regURL := hdl.buildURL()

	if Debug {
		fmt.Printf("DEBUG: regURL = %q of type %T\n\n", regURL, regURL)
	}

	// Use the HTTP(S) client defined in root.go on regURL to GET our response
	resp, err := Client.Get(regURL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Store the body of the response (which is JSON) in a body variable.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Type RegStatusList is a struct to represent the JSON response sent by the registrar.
	type RegStatusList struct {
		Code    int    `json:"code"`
		Status  string `json:"status"`
		Results struct {
			UUIDs []string `json:"uuids"`
		} `json:"results"`
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
	for _, v := range rl.Results.UUIDs {
		fmt.Println("Agent UUID:\t\t", v)
	}
	fmt.Println("-------\n")
}

// regAgentStatus returns the status of a keylime agent registered with a registrar
func regAgentStatus(a string) {
	// Type RegAgentStatus is a struct to represent the JSON response sent by the registrar when querying for a given agent UUID
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

	// Instantiate a handler for regAgentStatus, using config values.
	hdl := Handler{
		//Scheme:           C.General.TLS,
		Scheme: scheme,
		Host:   C.Tenant.RegistrarHost,
		Port:   C.Tenant.RegistrarPort,
		ApiVer: C.ApiVer,
		Path:   "agents",
	}

	// Add agent uuid to the path
	hdl.Path += "/" + uuid

	// Build query URL
	regURL := hdl.buildURL()

	fmt.Printf("DEBUG: regURL = %q of type %T\n\n", regURL, regURL)

	// GET on regURL to get our response
	resp, err := Client.Get(regURL)
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
		log.Fatalf("Error: agent \"%s\" doesn't exist on the registrar.\nPlease register the agent on the registrar and try again.\n", uuid)
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

func init() {
	statusCmd.AddCommand(registrarCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// registrarCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	registrarCmd.Flags().StringVarP(&uuid, "agent-uuid", "a", "", "Agent UUID to query")
	//setTLS()
}
