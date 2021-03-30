package cmd

import (
	"vervet/vervet"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List info of connected YubiKeys",
	Long:  `Shows data objects returned from YubiKey OpenPGP Application.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := vervet.ListYubiKeys()
		if err != nil {
			vervet.PrintFatal(err.Error(), 1)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
