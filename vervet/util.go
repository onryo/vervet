package vervet

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"vervet/yubikeyscard"
)

func ReadVaultUnsealKeyFile(path string, binary bool) ([]byte, error) {
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

func YubiKeyPrintInfo() error {
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

func fmtFingerprint(fp [20]byte) string {
	var fpString string

	for i := 0; i < len(fp); i += 2 {
		fpString = strings.ToUpper(fmt.Sprintf(fpString+"%x ", fp[i:i+2]))
	}

	return strings.TrimSpace(fpString[:24] + " " + fpString[24:])
}
