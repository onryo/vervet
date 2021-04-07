package cmd

import (
	"vervet/vervet"

	"github.com/spf13/cobra"
)

func init() {
	unsealServerSubCmd.Flags().IntVarP(&vaultPort, "port", "p", 8200, "Vault API port")
	unsealServerSubCmd.Flags().BoolVarP(&vaultTLSDisable, "insecure", "i", false, "disable TLS")

	unsealCmd.AddCommand(unsealServerSubCmd)
	unsealCmd.AddCommand(unsealClusterSubCmd)

	rootCmd.AddCommand(unsealCmd)

}

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseal Vault by server or cluster",
	Long:  `Decrypt PGP-encrypted unseal key and unseal Vault.`,
}

var unsealServerSubCmd = &cobra.Command{
	Use:   "server <vault address> <unseal key path>",
	Short: "Unseal Vault server",
	Long:  `Decrypt unseal key and unseal single Vault server.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		vaultAddr := getVaultAddress(args[0])
		keyPath := args[1]

		keys, err := vervet.ReadKeyFile(keyPath)
		if err != nil {
			vervet.PrintFatal(err.Error(), 1)
		}

		if err := vervet.Unseal([]string{vaultAddr}, keys); err != nil {
			vervet.PrintFatal(err.Error(), 1)
		}
	},
}

var unsealClusterSubCmd = &cobra.Command{
	Use:   "cluster <cluster name>",
	Short: "Unseal Vault cluster",
	Long:  `Decrypt unseal key and unseal Vault cluster.`,
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

		keys := cluster.Keys
		if cluster.KeyFile != "" {
			kf, err := vervet.ReadKeyFile(cluster.KeyFile)
			if err != nil {
				vervet.PrintFatal(err.Error(), 1)
			}

			keys = append(keys, kf...)
		}

		keys = vervet.Unique(keys)

		if err := vervet.Unseal(cluster.Servers, keys); err != nil {
			vervet.PrintFatal(err.Error(), 1)
		}
	},
}
