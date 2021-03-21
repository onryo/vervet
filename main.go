package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"syscall"
	"vault-yubikey-pgp-unseal/yubikeyscard"

	"github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh/terminal"
)

func die(err error) {
	fmt.Println("\U0001F6D1", err)
	os.Exit(1)
}

func promptPIN() ([]byte, error) {
	fmt.Print("\U0001F513 Enter YubiKey OpenPGP PIN: ")
	p, err := terminal.ReadPassword(int(syscall.Stdin))
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

func readUnsealKeyMsg(path string) ([]byte, error) {
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

func main() {
	// parse arg[0] for file name and read base64-encoded PGP message containing Vault unseal key
	flag.Parse()
	path := flag.Arg(0)
	unsealKeyMsg, err := readUnsealKeyMsg(path)
	if err != nil {
		die(err)
	}

	// connect YubiKey smart card interface, disconnect on return
	yk := new(yubikeyscard.YubiKey)
	if err := yk.Connect(); err != nil {
		die(err)
	}

	defer yk.Disconnect()

	// decrypt unseal key with DEK
	unsealKey, err := readUnsealKey(yk, unsealKeyMsg, promptPIN)
	if err != nil {
		die(err)
	}

	fmt.Println("\U0001F511 Decrypted Vault unseal key:", string(unsealKey))

	// connect to Vault server and execute unseal operation
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultURL, err := url.Parse(vaultAddr)
	if err != nil {
		die(err)
	}

	config := &api.Config{
		Address: vaultAddr,
	}
	client, err := api.NewClient(config)
	if err != nil {
		die(err)
	}

	sealStatusRsp, err := client.Sys().SealStatus()
	if err != nil {
		die(err)
	}

	if !sealStatusRsp.Sealed {
		err := errors.New("Vault server (" + vaultURL.Host + ") is already unsealed")
		die(err)
	}

	sealStatusRsp, err = client.Sys().Unseal(string(unsealKey))
	if err != nil {
		die(err)
	}

	if !sealStatusRsp.Sealed {
		fmt.Println("\u2705 Vault server (" + vaultURL.Host + ") is unsealed!")
	}
}
