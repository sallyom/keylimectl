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

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "keylime-tenant",
	Short: "A tool to interact with a Keylime cluster",
	Long: `keylime-tenant allows a user to interact with a Keylime cluster.
	
It provides acces to operations such as adding an agent, checking the status
of an agent or a verifier, and more.

To use keylime-tenant you need to have a keylime agent already running.

Find more information at github.com/keylime/keylime-tenant`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		//		fmt.Println("Get tls setting from config file (from cobra.Command Run):", viper.GetBool("general.enable_tls"))
		//		fmt.Printf("viper.Getbool is of type: %T\n", viper.GetBool("general.enable_tls"))
	},
}

func test() {
	fmt.Println("Get tls setting from config file:", viper.GetBool("enable_tls"))
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
		panic(fmt.Errorf("Fatal error using config file: %w \n", err))
	} else {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	fmt.Println("Get tls setting from config file (from init.Config):", viper.GetBool("general.enable_tls"))

	// We create a struct type named KlConf to hold the configuration data
	type KeylimeConf struct {
		RegistrarURL     string
		RegistrarPort    string
		RegistrarTLSPort string
	}
	// We instantiate a struct based on the KeylimeConf type with values from Viper
	Conf := KeylimeConf{
		RegistrarURL:     viper.GetString("registrar.registrar_ip"),
		RegistrarPort:    viper.GetString("registrar.registrar_port"),
		RegistrarTLSPort: viper.GetString("registrar.registrar_tls_port"),
	}
	fmt.Println("RegistrarURL is (from our struct):", Conf.RegistrarURL)
	// We could use viper.Unmarshal() here to unmarshal the values of the config
	// into a config object of type struct we will likely create.
	// err = viper.Unmarshal(&config)

}
