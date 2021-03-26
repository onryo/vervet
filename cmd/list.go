package cmd

import (
	"log"
	"vervet/vervet"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List info of connected YubiKeys",
	Long:  `Shows data objects returned from YubiKey OpenPGP Application.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := vervet.YubiKeyPrintInfo()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
