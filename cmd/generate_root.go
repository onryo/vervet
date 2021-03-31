package cmd

import (
	"vervet/vervet"

	"github.com/spf13/cobra"
)

func init() {
	generateRootServerSubCmd.Flags().IntVarP(&vaultPort, "port", "p", 8200, "Vault API port")
	generateRootServerSubCmd.Flags().BoolVarP(&vaultTLSDisable, "insecure", "i", false, "disable TLS")
	generateRootServerSubCmd.Flags().StringVarP(&vaultGenerateRootNonce, "nonce", "n", "", "nonce for root token generation")

	generateRootClusterSubCmd.Flags().StringVarP(&vaultGenerateRootNonce, "nonce", "n", "", "nonce for root token generation")

	generateRootCmd.AddCommand(generateRootServerSubCmd)
	generateRootCmd.AddCommand(generateRootClusterSubCmd)

	rootCmd.AddCommand(generateRootCmd)

}

var generateRootCmd = &cobra.Command{
	Use:   "generate-root",
	Short: "generate Vault root token",
	Long:  `Decrypt the unseal key and generate root token for Vault cluster.`,
}

var generateRootServerSubCmd = &cobra.Command{
	Use:   "server <vault address> <unseal key path> -n <nonce>",
	Short: "Generate root token for Vault cluster",
	Long:  `Decrypt the unseal key and generate Vault root token.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		vaultAddr := getVaultAddress(args[0])
		keyPath := args[1]

		keys, err := vervet.ReadKeyFile(keyPath)
		if err != nil {
			vervet.PrintFatal(err.Error(), 1)
		}

		if err := vervet.GenerateRoot(vaultAddr, keys); err != nil {
			vervet.PrintFatal(err.Error(), 1)
		}
	},
}

var generateRootClusterSubCmd = &cobra.Command{
	Use:   "cluster <cluster name> -n <nonce>",
	Short: "Generate root token for Vault cluster",
	Long:  `Decrypt the unseal key and generate Vault root token.`,
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

		if err := vervet.GenerateRoot(cluster.Servers[0], cluster.Keys); err != nil {
			vervet.PrintFatal(err.Error(), 1)
		}
	},
}
