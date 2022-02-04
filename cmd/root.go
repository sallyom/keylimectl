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
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// We create a struct type named KeylimeConf to hold the configuration data
type KeylimeConf struct {
	// Map the keylime.conf INI file's fields to Go variables, remapping the original names. A nested struct is needed because of how viper unmarshals INI. WORKS
	ApiVer string

	General struct {
		EnableTLS bool `mapstructure:"enable_TLS"`
	}

	Cloud_agent struct {
		AgentHost string `mapstructure:"cloudagent_ip"`
		VerifierAgentHost string `mapstructure:"cv_cloudagent"`
		AgentPort int `mapstructure:"cloudagent_port"`
	}

	Cloud_verifier struct {
		VerifierHost string `mapstructure:"cloudverifier_ip"`
		VerifierPort int    `mapstructure:"cloudverifier_port"`
	}
	
	Tenant struct {
		RegistrarHost string `mapstructure:"registrar_ip"`
		RegistrarPort int    `mapstructure:"registrar_port"`
	}

	Registrar struct {
		RegistrarTLSPort int `mapstructure:"registrar_tls_port"`
	}
	

	// Trying to map the INI file's fiels to our choice of Go Variables, without using a nested struct DOESN'T WORK (Tenant is not defined)
	// Tenant.RegistrarHost string `ini:regisrar_ip`
	// Tenant.RegistrarPort string `ini:regisrar_port`
	// Tenant.RegistrarTLSPort string `ini:regisrar_tls_port`

	// Trying to map our choice of variable names (RegistrarPort) to the INI file's fields: tenant --> registrar_port DOESN'T WORK
	// RegistrarURL     string `ini:"tenant.registrar_ip"`
	// RegistrarPort    int `ini:tenant.registrar_port`
	// RegistrarTLSPort int `registrar.registrar_tls_port`


	// Webapp not really used. Commenting for now.
	// Webapp struct {
	// 	WebappHost string `mapstructure:"webapp_ip"`
	// 	WebappPort int `mapstructure:"webapp_port"`
	// }

	// All these are used in the original tenant.py
	// Add them to our KeylimeConf struct as needed.
    // uuid_service_generate_locally = None
    // agent_uuid = None

    // K = None
    // V = None
    // U = None
    // auth_tag = None

    // tpm_policy = None
    // vtpm_policy = {}
    // metadata = {}
    // allowlist = {}
    // ima_sign_verification_keys = []
    // revocation_key = ""
    // accept_tpm_hash_algs = []
    // accept_tpm_encryption_algs = []
    // accept_tpm_signing_algs = []
    // mb_refstate = None

    // payload = None

    // tpm_instance = tpm()
}

var C KeylimeConf

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Version: "0.0.1",
	Use:   "keylime-tenant",
	Short: "A tool to interact with a Keylime cluster",
	Long: `keylime-tenant allows a user to interact with a Keylime cluster.
	
It provides acces to operations such as adding an agent, checking the status
of an agent or a verifier, and more.

To use keylime-tenant you need to have a keylime cluster already running.

Find more information at github.com/axelsimon/keylime-tenant`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		//		fmt.Println("Get tls setting from config file (from cobra.Command Run):", viper.GetBool("general.enable_tls"))
		//		fmt.Printf("viper.Getbool is of type: %T\n", viper.GetBool("general.enable_tls"))
	},
}

func test() {
	fmt.Println("DEBUG: Get tls setting from config file:", viper.GetBool("enable_tls"))
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/keylime.conf)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	// TODO: complete or remove
	//rootCmd.SetVersionTemplate('{{with .Name}}{{printf "keylimectl - %s " .}}{{end}}{{printf "Version: %s" .Version}}')
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
		// Keylime doesn't load a configuration from the home dir.
		// Disabling for now.
		//	} else {
		//		// Find home directory.
		//		home, err := os.UserHomeDir()
		//		cobra.CheckErr(err)
		//
		//		// Search config in home directory with name "keylime.conf" (without extension).
		//		viper.AddConfigPath(home)
		//		viper.SetConfigType("ini")
		//		viper.SetConfigName("keylime")
	} else {
		// Use default config from /etc/keylime.conf
		viper.AddConfigPath("/etc/")
		viper.SetConfigType("ini")
		viper.SetConfigName("keylime.conf")

	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	//if err := viper.ReadInConfig(); err == nil {
	//	fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	//}
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			fmt.Fprintf(os.Stderr, "Error, default config file not found. %v\n", viper.ConfigFileUsed())
		} else {
			// Config file was found but another error was produced
			panic(fmt.Errorf("Fatal error using default config file. %w \n", err))
		}
	} else {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	//fmt.Println(viper.Get("cloud_agent.cloudagent_port"))

	// We instantiate a struct based on the KeylimeConf type with values from Viper
	// Conf := KeylimeConf{
	// 	RegistrarURL:     viper.GetString("registrar.registrar_ip"),
	// 	RegistrarPort:    viper.GetString("registrar.registrar_port"),
	// 	RegistrarTLSPort: viper.GetString("registrar.registrar_tls_port"),
	// }

	// We could use viper.Unmarshal() here to unmarshal the values of the config
	// into a config object of type struct we will likely create.
	// err = viper.Unmarshal(&config)
	err := viper.Unmarshal(&C)
	if err != nil {
		panic(fmt.Errorf("unable to decode into struct, %v", err))
	}
	C.ApiVer = "v1"
	if C.General.EnableTLS {
		fmt.Println("TLS enabled. Good.")
	} else {
		fmt.Println("WARNING: TLS  is not enabled.")
	}
	fmt.Println("Using API version:", C.ApiVer)
	fmt.Printf("-----\nAre we getting a config written?\n\tWhat type?\t%T\n\tWhat value?\t%v\n\n", C, C)
	// fmt.Println("DEBUG: RegistrarHost is (from our conf struct):", C.Tenant.RegistrarHost)
	fmt.Println("DEBUG: RegistrarPort is (from our conf struct):", C.Tenant.RegistrarPort)
	// fmt.Println("DEBUG: RegistrarTLSPort is (from our conf struct):", C.Registrar.RegistrarTLSPort)
	fmt.Println("DEBUG: VerifierPort is (from our conf struct):", C.Cloud_verifier.VerifierPort)
	fmt.Println("DEBUG: end of rootCmd init\n\n")

}
