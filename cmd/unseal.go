package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"syscall"
	"vervet/yubikeypgp"
	"vervet/yubikeyscard"

	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	UnsealKeyPath   string
	UnsealKeyBinary bool
	VaultAddress    string
	VaultPort       int
	VaultTLSDisable bool
)

func init() {
	rootCmd.AddCommand(unsealCmd)

	unsealCmd.AddCommand(serverSubCmd)

	serverSubCmd.Flags().IntVarP(&VaultPort, "port", "p", 8200, "Vault API port")
	serverSubCmd.Flags().BoolVarP(&VaultTLSDisable, "no-tls", "n", false, "disable TLS")
	serverSubCmd.Flags().BoolVarP(&UnsealKeyBinary, "binary", "b", false, "read encrypted unseal key file as binary data")
	// unsealCmd.Flags().StringVarP(&VaultAddress, "address", "a", "", "address of Vault server to unseal")

}

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseal Vault by server or cluster",
	Long:  `Decrypt the unseal key and attempt to unseal Vault.`,
}

var serverSubCmd = &cobra.Command{
	Use:   "server <vault address> <unseal key>",
	Short: "Unseal Vault server(s)",
	Long:  `Decrypt the unseal key and attempt to unseal Vault.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		unsealKeyMsg, err := readUnsealKeyMsgFile(args[1], UnsealKeyBinary)
		if err != nil {
			fmt.Println("\U0001F6D1", err)
			return
		}

		unsealKey, err := getUnsealKey(unsealKeyMsg)
		if err != nil {
			fmt.Println("\U0001F6D1", err)
			return
		}

		vaultProtocol := "https"
		if VaultTLSDisable {
			vaultProtocol = "http"
		}

		vaultURL := url.URL{
			Scheme: vaultProtocol,
			Host:   args[0] + ":" + fmt.Sprintf("%d", VaultPort),
		}

		err = unsealVault(vaultURL.String(), unsealKey)
		if err != nil {
			fmt.Println("\U0001F6D1", err)
			return
		}
	},
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

func readUnsealKeyMsgFile(path string, binary bool) ([]byte, error) {
	var buf []byte
	var encKey []byte

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	buf, err = io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	if !binary {
		encKey, err = base64.StdEncoding.DecodeString(fmt.Sprintf("%s", buf))
		if err != nil {
			return nil, errors.New("encrypted unseal key file is not base64 encoded, use -b for binary PGP data")
		}
	} else {
		encKey = buf
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

	sealStatusRsp, err := client.Sys().Unseal(unsealKey)
	if err != nil {
		return err
	}

	printSealStatus(vaultURL, sealStatusRsp)

	return nil
}

func printSealStatus(url *url.URL, resp *api.SealStatusResponse) {
	fmt.Printf("Vault server: %s\n", url.Host)

	status := "unsealed"
	if resp.Sealed {
		status = "sealed"
	} else {
		fmt.Printf("Cluster name: %s\n", resp.ClusterName)
		fmt.Printf("Cluster ID: %s\n", resp.ClusterID)
	}

	if resp.Initialized {
		fmt.Printf("Seal Status: %s\n", status)
		fmt.Printf("Key Threshold/Shares: %d/%d\n", resp.T, resp.N)
		fmt.Printf("Progress: %d/%d\n", resp.Progress, resp.T)
		fmt.Printf("Version: %s\n", resp.Version)

	} else {
		fmt.Println("Vault server is not initialized.")
	}
}
