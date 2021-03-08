package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"syscall"

	"github.com/hashicorp/vault/api"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	pinMin int = 6
	pinMax int = 127
)

func die(err error) {
	fmt.Println("\U0001F6D1", err)
	os.Exit(1)
}

func getPIN() ([]byte, error) {
	fmt.Print("\U0001F513 Enter YubiKey OpenPGP PIN: ")
	p, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return []byte{}, err
	}

	fmt.Println()

	if len(p) < pinMin || len(p) > pinMax {
		return []byte{}, errors.New("Expected PIN length of 6-127 characters")
	}

	for i := range p {
		if p[i] < 0x30 || p[i] > 0x39 {

			return []byte{}, errors.New("Only digits 0-9 are valid PIN characters")
		}
	}

	return p, nil
}

func readUnsealKeyMsg(path string) []byte {
	file, err := os.Open(path)
	if err != nil {
		die(err)
	}
	defer file.Close()

	var contents string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		contents += scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		die(err)
	}

	encKey, err := base64.StdEncoding.DecodeString(contents)
	if err != nil {
		die(err)
	}

	return encKey
}

func main() {
	flag.Parse()
	path := flag.Arg(0)
	unsealKeyMsg := readUnsealKeyMsg(path)

	pin, err := getPIN()
	if err != nil {
		die(err)
	}

	sessionKey := readSessionKey(unsealKeyMsg, pin)

	if len(sessionKey) == 16 {
		fmt.Printf("\U0001F50D Found session key for PGP encrypted data packet: % x\n", sessionKey)
	} else {
		err := errors.New("Session key not found, exiting")
		die(err)
	}

	md, err := readMessage(bytes.NewReader(unsealKeyMsg), sessionKey, packet.CipherAES128)

	unsealKey, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		die(err)
	}

	fmt.Println("\U0001F511 Decrypted Vault unseal key:", string(unsealKey))

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
