package cmd

import (
	"fmt"
	"net/url"
	"vervet/vervet"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	config     VervetConfig
	configFile string

	vaultPort              int
	vaultTLSDisable        bool
	vaultGenerateRootNonce string

	rootCmd = &cobra.Command{
		Use:   "vervet",
		Short: "A utility for unsealing HashiCorp Vault with YubiKeys",
		Long: `Vervet is a CLI utility that streamlines Vault unseal operations. The tool will
decrypt PGP-encrypted Vault unseal key using the YubiKey OpenPGP applet.`,
	}
)

type VervetConfig struct {
	Clusters map[string][]*VaultClusterConfig `hcl:"cluster" mapstructure:"cluster"`
}

type VaultClusterConfig struct {
	Servers []string `hcl:"servers" mapstructure:"servers"`
	Keys    []string `hcl:"keys" mapstructure:"keys"`
	KeyFile string   `hcl:"key_file" mapstructure:"key_file"`
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.vervet/vervet.hcl)")
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

	viper.AutomaticEnv()
	viper.ReadInConfig()

	err := viper.Unmarshal(&config)
	if err != nil {
		vervet.PrintFatal(fmt.Sprintf("unable to decode into struct, %v", err), 1)
	}
}

func getVaultClusterConfig(clusterName string) (*VaultClusterConfig, error) {
	for name, cluster := range config.Clusters {
		if name == clusterName {
			return cluster[0], nil
		}
	}

	return nil, fmt.Errorf("config for Vault cluster '%s' not found", clusterName)
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

func getConfigDir() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", err
	}

	path := home + "/.vervet"

	return path, nil
}
