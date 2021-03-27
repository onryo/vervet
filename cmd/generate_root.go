package cmd

import (
	"log"
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

		if err := vervet.GenerateRootServer(vaultAddr, keyPath, keyFileBinary, vaultGenerateRootNonce); err != nil {
			log.Fatal(err)
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
			log.Fatal(err)
		}

		if err := vervet.GenerateRootCluster(cluster.Servers, cluster.Keys, vaultGenerateRootNonce); err != nil {
			log.Fatal(err)
		}
	},
}
