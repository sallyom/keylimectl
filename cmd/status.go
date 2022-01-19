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
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check status of a Keylime cluster",
	Long:  `Check the operational status of a Keylime cluster`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("status called")
		fmt.Println("Conf.RegistrarURL")
	},
}

// status = regstatus + cv status, so need reg response + cv response
// so: keylimectl status (all), keylme ctl status register and keylime ctl status cloudverifier?
// check for error codes: 404
// err := http.net
// log inconsistancy in responses between reg and cv
// return reg respons and cv response
func regStatus() {
	// Create a slice of string to hold URL and port
	str := []string{Conf.RegistrarURL, Conf.RegistrarPort}
	regURL := strings.Join(str, ":")
	resp, err := http.Get(regURL)
	fmt.Println(resp)
}

//func test() {
//	fmt.Println("Get tls setting from config file:", viper.GetBool("tls_enabled"))
//}

func init() {
	rootCmd.AddCommand(statusCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// statusCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// statusCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
