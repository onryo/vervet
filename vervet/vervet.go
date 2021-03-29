package vervet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"vervet/yubikeyscard"
)

// Unseal will decrypt the provided unseal key(s) and unseal each of the
// provided Vault cluster nodes.
func Unseal(vaultAddrs []string, encKeys []string) error {
	yk := new(yubikeyscard.YubiKey)
	if err := yk.Connect(); err != nil {
		return err
	}

	defer yk.Disconnect()

	var keys []string
	for _, encKey := range encKeys {
		key, err := decryptUnsealKey(yk, encKey)

		if err != nil {
			PrintWarning(err.Error())
		} else {
			keys = append(keys, key)
		}
	}

	if len(keys) > 0 {
		msg := fmt.Sprintf("decrypted %d of %d unseal key(s)", len(keys), len(encKeys))
		PrintSuccess(msg)

		for _, addr := range vaultAddrs {
			vault, err := newVaultClient(addr)
			if err != nil {
				return err
			}

			for _, key := range keys {
				_, err = vault.unseal(key)
				if err != nil {
					return err
				}
			}

			vault.printSealStatus()
		}
	} else {
		return errors.New("no unseal keys found, cannot proceed with unseal operation")
	}

	return nil
}

// GenerateRoot will decrypt the provided unseal key and enter the key share
// to progress the root generation attempt.
func GenerateRoot(vaultAddrs []string, keys []string, nonce string) error {
	yk := new(yubikeyscard.YubiKey)
	if err := yk.Connect(); err != nil {
		return err
	}

	defer yk.Disconnect()

	for _, addr := range vaultAddrs {
		vault, err := newVaultClient(addr)
		if err != nil {
			return err
		}

		for _, keyB64 := range keys {
			key, err := decryptUnsealKey(yk, keyB64)
			if err != nil {
				return err
			}

			err = vault.generateRoot(key, nonce)
			if err != nil {
				// if there is an issue, break the loop, and move to next server
				break
			}
		}
	}

	return nil
}

// ListYubiKeys will output the connected YubiKeys and the associated card and
// application-related data.
func ListYubiKeys() error {
	// connect YubiKey smart card interface, disconnect on return
	yk := new(yubikeyscard.YubiKey)
	if err := yk.Connect(); err != nil {
		return err
	}

	defer yk.Disconnect()

	ard := yk.AppRelatedData
	crd := yk.CardRelatedData

	fmt.Printf("Reader ...........: %s\n", yk.ReaderLabel)
	fmt.Printf("Application ID ...: %x%x%x%x%x%x\n",
		ard.AID.RID, ard.AID.App, ard.AID.Version,
		ard.AID.Manufacturer, ard.AID.Serial, ard.AID.RFU)
	fmt.Println("Application type .: OpenPGP")
	fmt.Printf("Version ..........: %d.%d\n",
		ard.AID.Version[0], ard.AID.Version[1])

	if ard.AID.Manufacturer[1] != 6 {
		return errors.New("unknown manufacturer, only Yubico yks supported")
	}

	fmt.Println("Manufacturer .....: Yubico")
	fmt.Printf("Serial number ....: %x\n", ard.AID.Serial)
	fmt.Printf("Name of cardholder: %s\n", strings.Replace(fmt.Sprintf("%s", crd.Name), "<<", " ", -1))
	fmt.Printf("Language prefs ...: %s\n", crd.LanguagePrefs)
	fmt.Printf("Salutation .......: %c\n", crd.Salutation)
	// URL of public key : [not set]
	// Login data .......: [not set]
	// Signature PIN ....: not forced
	fmt.Printf("Key attributes ...: rsa%d rsa%d rsa%d\n",
		binary.BigEndian.Uint16(ard.AlgoAttrSign.RSAModLen[:]),
		binary.BigEndian.Uint16(ard.AlgoAttrEnc.RSAModLen[:]),
		binary.BigEndian.Uint16(ard.AlgoAttrAuth.RSAModLen[:]))
	fmt.Printf("Max. PIN lengths .: %d %d %d\n",
		ard.PWStatus.PW1MaxLenFmt,
		ard.PWStatus.PW1MaxLenRC,
		ard.PWStatus.PW3MaxLenFmt)
	fmt.Printf("PIN retry counter : %d %d %d\n",
		ard.PWStatus.PW1RetryCtr,
		ard.PWStatus.PW1RCRetryCtr,
		ard.PWStatus.PW3RetryCtr)
	// Signature counter : 4
	// KDF setting ......: off
	fmt.Printf("Signature key ....: %s\n", fmtFingerprint(ard.Fingerprints.Sign))
	signGenDate := int64(binary.BigEndian.Uint32(ard.KeyGenDates.Sign[:]))
	fmt.Printf("      created ....: %s\n", time.Unix(signGenDate, 0))
	fmt.Printf("Encryption key....: %s\n", fmtFingerprint(ard.Fingerprints.Enc))
	encGenDate := int64(binary.BigEndian.Uint32(ard.KeyGenDates.Enc[:]))
	fmt.Printf("      created ....: %s\n", time.Unix(encGenDate, 0))
	fmt.Printf("Authentication key: %s\n", fmtFingerprint(ard.Fingerprints.Auth))
	authGenDate := int64(binary.BigEndian.Uint32(ard.KeyGenDates.Auth[:]))
	fmt.Printf("      created ....: %s\n", time.Unix(authGenDate, 0))

	return nil
}
