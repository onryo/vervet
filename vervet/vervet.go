package vervet

import (
	"encoding/binary"
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

	for i, addr := range vaultAddrs {
		vault, err := newVaultClient(addr)
		if err != nil {
			return err
		}

		resp, err := vault.unseal(keys)
		if err != nil {
			return err
		}

		if i == len(vaultAddrs)-1 {
			fmt.Println()
			PrintHeader("Vault Cluster Status")
			printSealStatus(resp)
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

	resp, err := vault.generateRoot(keys)
	if err != nil {
		return err
	}

	fmt.Println()
	PrintHeader("Root Token Generation Status")
	printGenRootStatus(resp)

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

// ListYubiKeys will output the basic details of connected YubiKeys.
func ListYubiKeys() error {
	// connect YubiKey smart card interface, disconnect on return
	yks := new(yubikeyscard.YubiKeys)
	if err := yks.Connect(); err != nil {
		return err
	}

	defer yks.Disconnect()

	for i, yk := range yks.YubiKeys {
		ard := yk.AppRelatedData
		crd := yk.CardRelatedData

		PrintHeader(fmt.Sprint(i+1, ": ", yk.ReaderLabel))
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

		if i < len(yks.YubiKeys)-1 {
			fmt.Println()
		}
	}

	return nil
}

// ShowYubiKey will search the connected YubiKeys for the specified serial
// number and output the details including smart card and application-related
// data.
func ShowYubiKey(sn string) error {
	// connect YubiKey smart card interface, disconnect on return
	yks := new(yubikeyscard.YubiKeys)
	if err := yks.Connect(); err != nil {
		return err
	}

	defer yks.Disconnect()

	yk := yks.FindBySN(sn)
	if yk == nil {
		return fmt.Errorf("could not locate YubiKey that supports OpenPGP with serial number '%s'", sn)
	}

	ard := yk.AppRelatedData
	crd := yk.CardRelatedData

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
