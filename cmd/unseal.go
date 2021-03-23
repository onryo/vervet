package cmd

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"syscall"
	"vault-yubikey-pgp-unseal/yubikeypgp"
	"vault-yubikey-pgp-unseal/yubikeyscard"

	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	UnsealKeyPath string
	VaultAddress  string
)

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseal Vault server(s)",
	Long:  `Decrypt the unseal key and attempt to unseal Vault.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		unsealKeyMsg, err := readUnsealKeyMsgFile(UnsealKeyPath)
		if err != nil {
			return err
		}

		unsealKey, err := getUnsealKey(unsealKeyMsg)
		if err != nil {
			return err
		}

		err = unsealVault(VaultAddress, unsealKey)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	unsealCmd.Flags().StringVarP(&UnsealKeyPath, "key", "k", "", "path to PGP-encrypted Vault unseal key")
	unsealCmd.Flags().StringVarP(&VaultAddress, "address", "a", "", "address of Vault server to unseal")

}

func promptPIN() ([]byte, error) {
	fmt.Print("\U0001F513 Enter YubiKey OpenPGP PIN: ")
	p, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return []byte{}, err
	}

	fmt.Println()

	if len(p) < 6 || len(p) > 127 {
		return []byte{}, errors.New("expected PIN length of 6-127 characters")
	}

	for i := range p {
		if p[i] < 0x30 || p[i] > 0x39 {
			return []byte{}, errors.New("only digits 0-9 are valid PIN characters")
		}
	}

	return p, nil
}

func readUnsealKeyMsgFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var contents string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		contents += scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	encKey, err := base64.StdEncoding.DecodeString(contents)
	if err != nil {
		return nil, err
	}

	return encKey, nil
}

func getUnsealKey(cipherTxt []byte) (string, error) {
	// connect YubiKey smart card interface, disconnect on return
	yk := new(yubikeyscard.YubiKey)
	if err := yk.Connect(); err != nil {
		return "", err
	}

	defer yk.Disconnect()

	// decrypt unseal key with DEK
	unsealKey, err := yubikeypgp.ReadUnsealKey(yk, cipherTxt, promptPIN)
	if err != nil {
		return "", err
	}

	fmt.Printf("\U0001F511 Decrypted Vault unseal key: %s\n", unsealKey)
	return string(unsealKey), nil
}

// connect to Vault server and execute unseal operation
func unsealVault(vaultAddr string, unsealKey string) error {
	if vaultAddr == "" {
		vaultAddr = os.Getenv("VAULT_ADDR")
	}

	vaultURL, err := url.Parse(vaultAddr)
	if err != nil {
		return err
	}

	config := &api.Config{
		Address: vaultAddr,
	}
	client, err := api.NewClient(config)
	if err != nil {
		return err
	}

	sealStatusRsp, err := client.Sys().SealStatus()
	if err != nil {
		return err
	}

	if !sealStatusRsp.Sealed {
		fmt.Println("\u2705 Vault server (" + vaultURL.Host + ") is already unsealed")
		return nil
	}

	sealStatusRsp, err = client.Sys().Unseal(unsealKey)
	if err != nil {
		return err
	}

	if !sealStatusRsp.Sealed {
		fmt.Println("\u2705 Vault server (" + vaultURL.Host + ") is unsealed!")
	}

	return nil
}
