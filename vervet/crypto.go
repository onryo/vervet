package vervet

import (
	"encoding/base64"
	"errors"
	"fmt"
	"syscall"
	"vervet/yubikeypgp"
	"vervet/yubikeyscard"

	"golang.org/x/term"
)

// decryptUnsealKey decrypts a base64-encoded PGP-encrypted Vault unseal key.
func decryptUnsealKey(yk *yubikeyscard.YubiKey, encryptedKeyB64 string) (string, error) {
	encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
	if err != nil {
		return "", errors.New("encrypted unseal key is not base64 encoded")
	}

	decryptedKey, err := yubikeypgp.Decrypt(yk, encryptedKey, promptPIN)
	if err != nil {
		return "", err
	}

	return string(decryptedKey), nil
}

// promptPin will read a PIN from an interactive terminal.
func promptPIN() ([]byte, error) {
	fmt.Print("\U0001F513 Enter YubiKey OpenPGP PIN: ")
	p, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return []byte{}, err
	}

	fmt.Printf("\n\n")

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
