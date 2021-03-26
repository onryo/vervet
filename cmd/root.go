package cmd

import (
	"fmt"
	"log"
	"net/url"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	config     VervetConfig
	configFile string

	unsealKeyFileBinary bool
	vaultPort           int
	vaultTLSDisable     bool

	rootCmd = &cobra.Command{
		Use:   "vervet",
		Short: "A utility for unsealing HashiCorp Vault with YubiKeys",
		Long: `Vervet is a CLI utility that streamlines Vault unseal
operations. The tool will decrypt PGP-encrypted Vault unseal key using 
the YubiKey OpenPGP applet.`,
	}
)

type VervetConfig struct {
	Clusters map[string][]*VaultClusterConfig `hcl:"cluster" mapstructure:"cluster"`
}

type VaultClusterConfig struct {
	Servers []string `hcl:"servers" mapstructure:"servers"`
	Keys    []string `hcl:"keys" mapstructure:"keys"`
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.cobra.yaml)")
	rootCmd.PersistentFlags().Bool("viper", true, "use Viper for configuration")

	// viper.BindPFlag("author", rootCmd.PersistentFlags().Lookup("author"))
	// viper.BindPFlag("useViper", rootCmd.PersistentFlags().Lookup("viper"))
}

func initConfig() {
	if configFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(configFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		cobra.CheckErr(err)

		// Search config in $HOME/vervet directory with name "vervet" (without extension).
		viper.AddConfigPath(home + "/.vervet")
		viper.SetConfigName("vervet")
		viper.SetConfigType("hcl")
	}

	// viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	err := viper.Unmarshal(&config)
	if err != nil {
		log.Fatalf("unable to decode into struct, %v", err)
	}
}

func getVaultClusterConfig(clusterName string) (*VaultClusterConfig, error) {
	for name, cluster := range config.Clusters {
		if name == clusterName {
			return cluster[0], nil
		}
	}

	return nil, fmt.Errorf("\U0001F6D1 config for Vault cluster '%s' not found", clusterName)
}

func getVaultAddress(host string) string {
	vaultProtocol := "https"
	if vaultTLSDisable {
		vaultProtocol = "http"
	}

	url := url.URL{
		Scheme: vaultProtocol,
		Host:   host + ":" + fmt.Sprintf("%d", vaultPort),
	}

	return url.String()
}
