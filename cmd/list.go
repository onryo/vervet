package cmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"vault-yubikey-pgp-unseal/yubikeyscard"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List info of connected YubiKeys",
	Long:  `Shows data objects returned from OpenPGP Application of YubiKey. `,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := printYubiKeyInfo()
		if err != nil {
			return err
		}

		return nil
	},
}

func printYubiKeyInfo() error {
	// connect YubiKey smart card interface, disconnect on return
	yk := new(yubikeyscard.YubiKey)
	if err := yk.Connect(); err != nil {
		return err
	}

	defer yk.Disconnect()

	fmt.Printf("Reader ...........: %s\n", yk.ReaderLabel)
	fmt.Printf("Application ID ...: %x%x%x%x%x%x\n",
		yk.AppRelatedData.AID.RID,
		yk.AppRelatedData.AID.App,
		yk.AppRelatedData.AID.Version,
		yk.AppRelatedData.AID.Manufacturer,
		yk.AppRelatedData.AID.Serial,
		yk.AppRelatedData.AID.RFU)
	fmt.Println("Application type .: OpenPGP")
	fmt.Printf("Version ..........: %d.%d\n",
		yk.AppRelatedData.AID.Version[0],
		yk.AppRelatedData.AID.Version[1])

	if yk.AppRelatedData.AID.Manufacturer[1] != 6 {
		return errors.New("unknown manufacturer, only Yubico yks supported")
	}
	fmt.Println("Manufacturer .....: Yubico")
	fmt.Printf("Serial number ....: %x\n", yk.AppRelatedData.AID.Serial)
	fmt.Printf("Name of cardholder: %s\n", yk.CardRelatedData.Name)
	fmt.Printf("Language prefs ...: %s\n", yk.CardRelatedData.LanguagePrefs)
	fmt.Printf("Salutation .......: %c\n", yk.CardRelatedData.Salutation)
	// URL of public key : [not set]
	// Login data .......: [not set]
	// Signature PIN ....: not forced
	fmt.Printf("Key attributes ...: rsa%d rsa%d rsa%d\n",
		binary.BigEndian.Uint16(yk.AppRelatedData.AlgoAttrSign.RSAModLen[:]),
		binary.BigEndian.Uint16(yk.AppRelatedData.AlgoAttrEnc.RSAModLen[:]),
		binary.BigEndian.Uint16(yk.AppRelatedData.AlgoAttrAuth.RSAModLen[:]))
	fmt.Printf("Max. PIN lengths .: %d %d %d\n",
		yk.AppRelatedData.PWStatus.PW1MaxLenFmt,
		yk.AppRelatedData.PWStatus.PW1MaxLenRC,
		yk.AppRelatedData.PWStatus.PW3MaxLenFmt)
	fmt.Printf("PIN retry counter : %d %d %d\n",
		yk.AppRelatedData.PWStatus.PW1RetryCtr,
		yk.AppRelatedData.PWStatus.PW1RCRetryCtr,
		yk.AppRelatedData.PWStatus.PW3RetryCtr)
	// Signature counter : 4
	// KDF setting ......: off
	fmt.Printf("Signature key ....: %x\n", yk.AppRelatedData.Fingerprints.Sign)
	signGenDate := int64(binary.BigEndian.Uint32(yk.AppRelatedData.KeyGenDates.Sign[:]))
	fmt.Printf("\tcreated ....: %s\n", time.Unix(signGenDate, 0))
	fmt.Printf("Encryption key....: %x\n", yk.AppRelatedData.Fingerprints.Enc)
	encGenDate := int64(binary.BigEndian.Uint32(yk.AppRelatedData.KeyGenDates.Enc[:]))
	fmt.Printf("\tcreated ....: %s\n", time.Unix(encGenDate, 0))
	fmt.Printf("Authentication key: %x\n", yk.AppRelatedData.Fingerprints.Auth)
	authGenDate := int64(binary.BigEndian.Uint32(yk.AppRelatedData.KeyGenDates.Auth[:]))
	fmt.Printf("\tcreated ....: %s\n", time.Unix(authGenDate, 0))

	return nil
}

func fmtFingerprint(fp [20]byte) string {
	var fpString string

	for i := 0; i < len(fp); i += 4 {
		sep := " "
		if i == 4 {
			sep = " "
		}

		fpString = fpString + string(fp[i:i+4]) + sep
	}

	return strings.TrimSpace(fpString)
}
