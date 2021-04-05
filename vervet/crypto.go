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

const (
	unsealKeyLengthMin int = 16
	unsealKeyLengthMax int = 33
)

// decryptUnsealKeys wraps decryptUnsealKey to decrypt a slice of unseal keys
// and provide console messages.
func decryptUnsealKeys(encryptedKeys []string) ([]string, error) {
	yks := new(yubikeyscard.YubiKeys)
	if err := yks.Connect(); err != nil {
		return nil, err
	}

	defer yks.Disconnect()

	var keys []string
	for _, ek := range encryptedKeys {
		key, err := decryptUnsealKey(yks, ek)
		if err != nil {
			PrintWarning(err.Error())
		} else {
			keys = append(keys, key)
		}
	}

	if len(keys) == 0 {
		return nil, errors.New("no Vault unseal keys found, cannot proceed with unseal operation")
	}

	msg := fmt.Sprintf("decrypted %d Vault unseal key(s)", len(keys))
	PrintSuccess(msg)

	return keys, nil
}

// decryptUnsealKey performs a base64 decode, then decrypts a PGP-encrypted
// Vault unseal key.
func decryptUnsealKey(yks *yubikeyscard.YubiKeys, cipherTxtB64 string) (unsealKey string, err error) {
	encryptedKey, err := base64.StdEncoding.DecodeString(cipherTxtB64)
	if err != nil {
		err = errors.New("encrypted unseal key is not base64 encoded")
		return
	}

	retries := 1
	for retries > 0 {
		md, retries, err := yubikeypgp.ReadMessage(yks, encryptedKey, promptPIN)
		if err != nil {
			switch {
			case retries == 0:
				return "", errors.New("PIN bank locked, no retries remaining")
			case retries < 0:
				return "", err
			default:
				PrintError(err.Error())
				continue
			}
		}

		serial := md.YubiKey.AppRelatedData.AID.Serial
		PrintInfo(fmt.Sprintf("decrypted unseal key with key ID %X found on YubiKey %x", md.DecryptedWith, serial))

		unsealKey = string(md.Body)
		break
	}

	// unsealKey is a byte slice of unicode characters, divide length by 2 to get raw byte length
	n := len(unsealKey) / 2
	if n < unsealKeyLengthMin {
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
