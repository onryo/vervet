package cmd

import (
	"encoding/base64"
	"fmt"
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
	Short: "generate root token for Vault cluster",
	Long:  `Decrypt the unseal key and generate root token for Vault cluster.`,
}

var generateRootServerSubCmd = &cobra.Command{
	Use:   "server <vault address> <unseal key> -n <nonce>",
	Short: "Generate root token for Vault cluster",
	Long:  `Decrypt the unseal key and generate root token for Vault cluster.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		server := args[0]
		generateRootKeyPath := args[1]

		generateRootKeyMsg, err := vervet.ReadVaultUnsealKeyFile(generateRootKeyPath, unsealKeyFileBinary)
		if err != nil {
			log.Fatal(err)
		}

		unsealKey, err := vervet.YubiKeyDecrypt(generateRootKeyMsg)
		if err != nil {
			log.Fatal(err)
		}

		vaultAddr := getVaultAddress(server)

		err = vervet.VaultGenerateRoot(vaultAddr, unsealKey, vaultGenerateRootNonce)
		if err != nil {
			log.Fatal(err)
		}
	},
}

var generateRootClusterSubCmd = &cobra.Command{
	Use:   "cluster <cluster name> -n <nonce>",
	Short: "Generate root token for Vault cluster",
	Long:  `Decrypt the unseal key and generate root token for Vault cluster.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		clusterName := args[0]

		cluster, err := getVaultClusterConfig(clusterName)
		if err != nil {
			fmt.Println(err)
			return
		}

		for _, server := range cluster.Servers {
			for _, keyB64 := range cluster.Keys {
				key, err := base64.StdEncoding.DecodeString(keyB64)
				if err != nil {
					log.Fatal("encrypted generateRoot key file is not base64 encoded, use -b for binary PGP data")
				}

				generateRootKey, err := vervet.YubiKeyDecrypt(key)
				if err != nil {
					log.Fatal(err)
				}

				err = vervet.VaultGenerateRoot(server, generateRootKey, vaultGenerateRootNonce)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	},
}
