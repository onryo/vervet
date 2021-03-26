package cmd

import (
	"encoding/base64"
	"fmt"
	"vervet/vervet"

	"github.com/spf13/cobra"
)

func init() {
	serverSubCmd.Flags().IntVarP(&vaultPort, "port", "p", 8200, "Vault API port")
	serverSubCmd.Flags().BoolVarP(&vaultTLSDisable, "no-tls", "n", false, "disable TLS")
	serverSubCmd.Flags().BoolVarP(&unsealKeyFileBinary, "binary", "b", false, "read encrypted unseal key file as binary data")

	unsealCmd.AddCommand(serverSubCmd)
	unsealCmd.AddCommand(clusterSubCmd)

	rootCmd.AddCommand(unsealCmd)

}

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseal Vault by server or cluster",
	Long:  `Decrypt the unseal key and attempt to unseal Vault.`,
}

var serverSubCmd = &cobra.Command{
	Use:   "server <vault address> <unseal key>",
	Short: "Unseal Vault server",
	Long:  `Decrypt unseal key and attempt to unseal Vault server.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		server := args[0]
		unsealKeyPath := args[1]

		unsealKeyMsg, err := vervet.ReadUnsealKeyFile(unsealKeyPath, unsealKeyFileBinary)
		if err != nil {
			fmt.Println("\U0001F6D1", err)
			return
		}

		unsealKey, err := vervet.DecryptUnsealKey(unsealKeyMsg)
		if err != nil {
			fmt.Println("\U0001F6D1", err)
			return
		}

		vaultAddr := getVaultAddress(server)

		err = vervet.UnsealVault(vaultAddr, unsealKey)
		if err != nil {
			fmt.Println("\U0001F6D1", err)
			return
		}
	},
}

var clusterSubCmd = &cobra.Command{
	Use:   "cluster <cluster name>",
	Short: "Unseal Vault cluster",
	Long:  `Decrypt unseal key and attempt to unseal Vault cluster.`,
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
					fmt.Println("encrypted unseal key file is not base64 encoded, use -b for binary PGP data")
				}

				unsealKey, err := vervet.DecryptUnsealKey(key)
				if err != nil {
					fmt.Println("\U0001F6D1", err)
					return
				}

				err = vervet.UnsealVault(server, unsealKey)
				if err != nil {
					fmt.Println("\U0001F6D1", err)
					return
				}
			}
		}
	},
}
