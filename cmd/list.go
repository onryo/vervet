package cmd

import (
	"fmt"
	"vervet/vervet"

	"github.com/spf13/cobra"
)

func init() {
	listCmd.AddCommand(listClustersSubCmd)
	listCmd.AddCommand(listYubiKeysSubCmd)

	rootCmd.AddCommand(listCmd)
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List connected YubiKeys and configured Vault clusters",
	Long:  `List connected YubiKeys and configured Vault clusters.`,
}

var listClustersSubCmd = &cobra.Command{
	Use:   "clusters",
	Short: "List Vault clusters",
	Long:  `List Vault clusters in Vervet configuration file.`,
	Run: func(cmd *cobra.Command, args []string) {
		i := 0
		for name, cluster := range config.Clusters {
			vervet.PrintHeader(name)
			vervet.PrintKVSlice("Server(s)", cluster[0].Servers)
			vervet.PrintKV("Key(s)", fmt.Sprintf("%d", len(cluster[0].Keys)))

			if i < len(config.Clusters)-1 {
				fmt.Println()
			}

			i++
		}
	},
}

var listYubiKeysSubCmd = &cobra.Command{
	Use:   "yubikeys",
	Short: "List connected YubiKeys",
	Long:  `List overview of connected YubiKeys.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := vervet.ListYubiKeys()
		if err != nil {
			vervet.PrintFatal(err.Error(), 1)
		}
	},
}
