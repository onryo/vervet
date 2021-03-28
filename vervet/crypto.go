package vervet

import (
	"encoding/base64"
	"errors"
	"fmt"
	"syscall"
	"vervet/yubikeypgp"
	"vervet/yubikeyscard"

	"github.com/logrusorgru/aurora"
	"golang.org/x/term"
)

const unsealKeyLengthMin int = 16
const unsealKeyLengthMax int = 33

// decryptUnsealKey performs a base64 decode, then decrypts a PGP-encrypted
// Vault unseal key.
func decryptUnsealKey(yk *yubikeyscard.YubiKey, cipherTxtB64 string) (unsealKey string, err error) {
	encryptedKey, err := base64.StdEncoding.DecodeString(cipherTxtB64)
	if err != nil {
		err = errors.New("encrypted unseal key is not base64 encoded")
		return
	}

	retries := 1
	for retries > 0 {
		plainTxtBytes, retries, err := yubikeypgp.Decrypt(yk, encryptedKey, promptPIN)
		if err != nil && retries < 1 {
			return "", errors.New("PIN bank locked, no retries remaining")
		} 

		if err != nil && retries > 0 {
			msg := fmt.Sprintf("[error] %v", err)
			fmt.Println(aurora.Red(msg))
			continue
		}

		unsealKey = string(plainTxtBytes)
		break
		
	}

	// unsealKey is a byte slice of unicode characters, divide length by 2 to get raw byte length
	n := len(unsealKey)/2
	if  n < unsealKeyLengthMin {
		err = fmt.Errorf("unseal key length is shorter than minimum %d bytes", unsealKeyLengthMin)
		return 
	}
	if n > unsealKeyLengthMax {
		err = fmt.Errorf("unseal key length is longer than maximum %d bytes", unsealKeyLengthMax)
		return 
	}

	return
}

// promptPin will read a PIN from an interactive terminal.
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
