package cmd

import (
	"encoding/base64"
	"log"
	"vervet/vervet"

	"github.com/spf13/cobra"
)

func init() {
	unsealServerSubCmd.Flags().IntVarP(&vaultPort, "port", "p", 8200, "Vault API port")
	unsealServerSubCmd.Flags().BoolVarP(&vaultTLSDisable, "insecure", "i", false, "disable TLS")
	unsealServerSubCmd.Flags().BoolVarP(&unsealKeyFileBinary, "binary", "b", false, "read encrypted unseal key file as binary data (default: base64)")

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
		server := args[0]
		unsealKeyPath := args[1]

		unsealKeyMsg, err := vervet.ReadVaultUnsealKeyFile(unsealKeyPath, unsealKeyFileBinary)
		if err != nil {
			log.Fatal(err)
		}

		unsealKey, err := vervet.YubiKeyDecrypt(unsealKeyMsg)
		if err != nil {
			log.Fatal(err)
		}

		vaultAddr := getVaultAddress(server)

		err = vervet.VaultUnseal(vaultAddr, unsealKey)
		if err != nil {
			log.Fatal(err)
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
			log.Fatal(err)
		}

		for _, server := range cluster.Servers {
			for _, keyB64 := range cluster.Keys {
				key, err := base64.StdEncoding.DecodeString(keyB64)
				if err != nil {
					log.Fatal("encrypted unseal key file is not base64 encoded, use -b for binary PGP data")
				}

				unsealKey, err := vervet.YubiKeyDecrypt(key)
				if err != nil {
					log.Fatal(err)
				}

				err = vervet.VaultUnseal(server, unsealKey)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	},
}
