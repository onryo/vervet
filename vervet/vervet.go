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
func Unseal(vaultAddrs []string, encryptedKeys []string) error {
	keys, err := decryptUnsealKeys(encryptedKeys)
	if err != nil {
		return err
	}

	for _, addr := range vaultAddrs {
		vault, err := newVaultClient(addr)
		if err != nil {
			return err
		}

		if err = vault.unseal(keys); err != nil {
			return err
		}
	}

	return nil
}

// GenerateRoot will decrypt the provided unseal key and enter the key share
// to progress the root generation attempt.
func GenerateRoot(vaultAddr string, encryptedKeys []string) error {
	keys, err := decryptUnsealKeys(encryptedKeys)
	if err != nil {
		return err
	}

	vault, err := newVaultClient(vaultAddr)
	if err != nil {
		return err
	}

	if err = vault.generateRoot(keys); err != nil {
		return err
	}

	return nil
}

// ListVaultStatus will output of the status the provided Vault address.
func ListVaultStatus(vaultAddr string) error {
	vault, err := newVaultClient(vaultAddr)
	if err != nil {
		return err
	}

	resp, err := vault.apiClient.Sys().SealStatus()
	if err != nil {
		return err
	}

	printSealStatus(resp)

	return nil
}

// ListYubiKeys will output the connected YubiKeys and basic details.
func ListYubiKeys() error {
	// connect YubiKey smart card interface, disconnect on return
	yk := new(yubikeyscard.YubiKey)
	if err := yk.Connect(); err != nil {
		return err
	}

	defer yk.Disconnect()

	ard := yk.AppRelatedData
	crd := yk.CardRelatedData

	PrintHeader(yk.ReaderLabel)
	PrintKV("Manufacturer", "Yubico")
	PrintKV("Serial number", fmt.Sprintf("%x", ard.AID.Serial))

	if crd.Name != nil {
		PrintKV("Name of cardholder", strings.Replace(fmt.Sprintf("%s", crd.Name), "<<", " ", -1))
	}

	PrintKV("Signature key", fmt.Sprintf("rsa%d/%s",
		binary.BigEndian.Uint16(ard.AlgoAttrSign.RSAModLen[:]),
		fmtFingerprintTerse(ard.Fingerprints.Sign)))
	PrintKV("Encryption key", fmt.Sprintf("rsa%d/%s",
		binary.BigEndian.Uint16(ard.AlgoAttrEnc.RSAModLen[:]),
		fmtFingerprintTerse(ard.Fingerprints.Enc)))
	PrintKV("Authentication key", fmt.Sprintf("rsa%d/%s",
		binary.BigEndian.Uint16(ard.AlgoAttrAuth.RSAModLen[:]),
		fmtFingerprintTerse(ard.Fingerprints.Auth)))

	return nil
}

// ShowYubiKey will output the connected YubiKey and associated card and
// application-related data.
func ShowYubiKey() error {
	// connect YubiKey smart card interface, disconnect on return
	yk := new(yubikeyscard.YubiKey)
	if err := yk.Connect(); err != nil {
		return err
	}

	defer yk.Disconnect()

	ard := yk.AppRelatedData
	crd := yk.CardRelatedData

	if ard.AID.Manufacturer[1] != 6 {
		return errors.New("unknown manufacturer, only Yubico yks supported")
	}

	PrintHeader("YubiKey Status")

	PrintKV("Reader", yk.ReaderLabel)
	PrintKV("Application ID", fmt.Sprintf("%x%x%x%x%x%x",
		ard.AID.RID, ard.AID.App, ard.AID.Version,
		ard.AID.Manufacturer, ard.AID.Serial, ard.AID.RFU))
	PrintKV("Application type", "OpenPGP")
	PrintKV("Version", fmt.Sprintf("%d.%d", ard.AID.Version[0], ard.AID.Version[1]))
	PrintKV("Manufacturer", "Yubico")
	PrintKV("Serial number", fmt.Sprintf("%x", ard.AID.Serial))
	PrintKV("Name of cardholder", strings.Replace(fmt.Sprintf("%s", crd.Name), "<<", " ", -1))
	PrintKV("Language prefs", string(crd.LanguagePrefs))

	switch crd.Salutation {
	case 0x30:
		PrintKV("Pronoun", "unspecified")
	case 0x31:
		PrintKV("Pronoun", "he")
	case 0x32:
		PrintKV("Pronoun", "he")
	case 0x39:
		PrintKV("Pronoun", "they")
	}

	PrintKV("Max. PIN lengths", fmt.Sprintf("%d %d %d",
		ard.PWStatus.PW1MaxLenFmt,
		ard.PWStatus.PW1MaxLenRC,
		ard.PWStatus.PW3MaxLenFmt))
	PrintKV("PIN retry counter", fmt.Sprintf("%d %d %d",
		ard.PWStatus.PW1RetryCtr,
		ard.PWStatus.PW1RCRetryCtr,
		ard.PWStatus.PW3RetryCtr))

	PrintKV("Signature key", fmtFingerprint(ard.Fingerprints.Sign))
	PrintKV("    algorithm", fmt.Sprintf("rsa%d",
		binary.BigEndian.Uint16(ard.AlgoAttrSign.RSAModLen[:])))
	signGenDate := int64(binary.BigEndian.Uint32(ard.KeyGenDates.Sign[:]))
	PrintKV("    created", time.Unix(signGenDate, 0).String())

	PrintKV("Encryption key", fmtFingerprint(ard.Fingerprints.Enc))
	PrintKV("    algorithm", fmt.Sprintf("rsa%d",
		binary.BigEndian.Uint16(ard.AlgoAttrEnc.RSAModLen[:])))
	encGenDate := int64(binary.BigEndian.Uint32(ard.KeyGenDates.Enc[:]))
	PrintKV("    created", time.Unix(encGenDate, 0).String())

	PrintKV("Authentication key", fmtFingerprint(ard.Fingerprints.Auth))
	PrintKV("    algorithm", fmt.Sprintf("rsa%d",
		binary.BigEndian.Uint16(ard.AlgoAttrAuth.RSAModLen[:])))
	authGenDate := int64(binary.BigEndian.Uint32(ard.KeyGenDates.Auth[:]))
	PrintKV("    created", time.Unix(authGenDate, 0).String())

	return nil
}
