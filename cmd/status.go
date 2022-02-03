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

	// "net/url"

	"github.com/spf13/cobra"
	"k8s.io/klog"
)

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check status of a Keylime cluster",
	Long:  `Check the operational status of a Keylime cluster`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("DEBUG: begin run registrar status")
		regStatus()
		//fmt.Println("DEBUG: begin run verifier status")
		//cvStatus()
	},
}

// OUTLINE:
// status = regstatus + cv status, so need reg response + cv response
// planned command and subcommands: keylimectl status (all), keylmectl status register and keylimectl status (cloud)verifier?
// check for error codes: 404
// use a timeout:
// timeout := time.Duration(5 * time.Second)
// client := http.Client{
//     Timeout: timeout,
// }
// client.Get(url)
// check errors:
// err := http.net
// log inconsistency in responses between reg and cv
// return reg response and cv response

// Handler type is a struct to hold our configuration elements, from which to build the requested URL.
type Handler struct {
	Scheme string
	Host   string
	Port   int
	ApiVer string
	Path   string
}

func regStatus() {
	// Build a handler for a subset of our config (taken from Shiori)
	// This should be reusable for cvlist, cvstatus, etc.

	// Instantiate a handler for regStatus, using config values. This might need to be scoped to the package rather than the function.
	hdl := Handler{
		//Scheme:           C.General.TLS,
		Scheme: "http://",
		Host:   C.Tenant.RegistrarHost,
		Port:   C.Tenant.RegistrarPort,
		ApiVer: C.ApiVer,
		Path:   "agents",
	}

	klog.Infof("DEBUG: What does hdl look like? %s", hdl)

	// This next line is now done in its own Handler method: buildURL
	// RegURL := Scheme + C.Tenant.RegistrarHost + ":" + string(C.Tenant.RegistrarPort) + "/" + C.ApiVer + "/" + RegPath
	regURL := hdl.buildURL()

	fmt.Printf("DEBUG: regURL = %q of type %T\n\n", regURL, regURL)

	// GET on regURL to get our response
	resp, err := http.Get(regURL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Store the body of the response (which is JSON) in a body variable.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Type RegStatus is a struct to represent the JSON response sent by the registrar.
	type RegStatus struct {
		Code    int    `json:"code"`
		Status  string `json:"status"`
		Results struct {
			UUIDs []string `json:"uuids"`
		} `json:"results"`
	}

	// Unmarshal the JSON status into a RegStatus Go struct
	var rStatus RegStatus
	err = json.Unmarshal(body, &rStatus)
	if err != nil {
		log.Fatal(err)
	}

	// Print out the relevant fields of the registrar's status
	fmt.Println("Keylime registrar status:")
	fmt.Println("-------")
	fmt.Println("Status:\t\t", rStatus.Status)
	fmt.Println("Code:\t\t", rStatus.Code)
	fmt.Println("-------")
	fmt.Println("Results:")
	for _, v := range rStatus.Results.UUIDs {
		fmt.Println("UUID:\t\t", v)
	}
	fmt.Println("-------")
}

func cvStatus() {
	fmt.Println("Called cvStatus")
}

// There must be a nicer way to do this.
func (h *Handler) buildURL() string {
	return h.Scheme + h.Host + ":" + fmt.Sprint(h.Port) + "/" + h.ApiVer + "/" + h.Path
}

func init() {
	rootCmd.AddCommand(statusCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command and all subcommands, e.g.:
	// We use Persistent Flags to pass them down to the "status verifier" and "status registrar" commands
	// statusCmd.PersistentFlags().StringP("registrar-host", "rh", "127.0.0.1", "the hostname or IP address of the registrar to query")
	// statusCmd.PersistentFlags().StringP("registrar-port", "rp", "8891", "the port of the registrar to query")
	// statusCmd.PersistentFlags().StringP("verifier-host", "vh", "127.0.0.1", "the hostname or IP address of the verifier to query")
	// statusCmd.PersistentFlags().StringP("verifier-port", "vp", "8881", "the port of the verifier to query")
	// statusCmd.PersistentFlags().StringP("verifier-id", "vi", "", "the unique identifier of a cloud verifier to query")
	// TODO: use PersistentFlags().String or PersistentFlags().StringVarP ?
	//statusCmd.PersistentFlags().StringVarP(&verifierhost, "verifier-host", "vh", "127.0.0.1", "the hostname or IP address of the registrar to query")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	statusCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
