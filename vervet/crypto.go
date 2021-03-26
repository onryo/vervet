package vervet

import (
	"errors"
	"fmt"
	"syscall"
	"vervet/yubikeypgp"
	"vervet/yubikeyscard"

	"golang.org/x/term"
)

func DecryptUnsealKey(cipherTxt []byte) (string, error) {
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
