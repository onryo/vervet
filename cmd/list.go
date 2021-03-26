package cmd

import (
	"vervet/vervet"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List info of connected YubiKeys",
	Long:  `Shows data objects returned from OpenPGP Application of YubiKey. `,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := vervet.PrintYubiKeyInfo()
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
