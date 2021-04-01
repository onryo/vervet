package cmd

import (
	"fmt"
	"vervet/vervet"

	"github.com/spf13/cobra"
)

func init() {
	showCmd.AddCommand(showClusterSubCmd)
	showCmd.AddCommand(showYubikeySubCmd)

	rootCmd.AddCommand(showCmd)
}

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show details of YubiKeys and Vault clusters",
	Long:  `Show details of YubiKeys and Vault clusters.`,
}

var showClusterSubCmd = &cobra.Command{
	Use:   "cluster <cluster name>",
	Short: "Show Vault cluster status",
	Long:  `Show overview and unseal status of the specified Vault cluster.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		clusterName := args[0]

		cluster, err := getVaultClusterConfig(clusterName)
		if err != nil {
			vervet.PrintFatal(err.Error(), 1)
		}

		if len(cluster.Servers) == 0 {
			vervet.PrintFatal("no Vault servers in configuration", 1)
		}

		vervet.PrintHeader("Vault Cluster Status")
		vervet.PrintKVSlice("Server(s)", cluster.Servers)
		vervet.PrintKV("Key(s)", fmt.Sprintf("%d", len(cluster.Keys)))

		if err := vervet.ListVaultStatus(cluster.Servers[0]); err != nil {
			vervet.PrintFatal(err.Error(), 1)
		}
	},
}

var showYubikeySubCmd = &cobra.Command{
	Use:   "yubikey <serial number>",
	Short: "Show YubiKey details",
	Long:  `Show YubiKey details returned from OpenPGP application data objects.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sn := args[0]

		err := vervet.ShowYubiKey(sn)
		if err != nil {
			vervet.PrintFatal(err.Error(), 1)
		}
	},
}
