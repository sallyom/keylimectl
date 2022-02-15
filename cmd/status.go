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
	// "encoding/json"
	"fmt"
	// "io/ioutil"
	// "log"
	// "net/http"
	// "net/url"

	"github.com/spf13/cobra"
)

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check status of a Keylime cluster",
	Long:  `Check the operational status of a Keylime cluster`,
	Run: func(cmd *cobra.Command, args []string) {
		keylimeOpts.initConfig(cmd)
	},
}

// Handler type is a struct to hold our configuration elements, from which to build the requested URL.
type Handler struct {
	Scheme string
	Host   string
	Port   int
	ApiVer string
	Path   string
}

// There must be a nicer way to do this.
func (h *Handler) buildURL() string {
	return h.Scheme + h.Host + ":" + fmt.Sprint(h.Port) + "/" + h.ApiVer + "/" + h.Path
}
