package cmd

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "vervet",
		Short: "A utility for unsealing HashiCorp Vault with YubiKeys",
		Long: `Vervet is a CLI utility that streamlines Vault unseal
operations. The tool will decrypt PGP-encrypted Vault unseal key using 
the YubiKey OpenPGP applet.`,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cobra.yaml)")
	// rootCmd.PersistentFlags().StringP("author", "a", "YOUR NAME", "author name for copyright attribution")
	// rootCmd.PersistentFlags().StringVarP(&userLicense, "license", "l", "", "name of license for the project")
}
