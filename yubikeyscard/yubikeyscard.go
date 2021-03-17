package yubikeyscard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/ebfe/scard"
	"golang.org/x/crypto/ssh/terminal"
)

// YubiKeys represents the system context and slice of connected smart cards

const (
	pinMin int = 6
	pinMax int = 127
)

const (
	AlgoIdRSA   uint8 = 1
	AlgoIdECDH  uint8 = 12
	AlgoIdECDSA uint8 = 13
)

type YubiKey struct {
	Context *scard.Context
	Card    *scard.Card
}

type AppRelatedData struct {
	AID          AID
	AlgoAttrSign AlgoAttr
	AlgoAttrEnc  AlgoAttr
	AlgoAttrAuth AlgoAttr
	PWStatus     PWStatus
	Fingerprints Fingerprints
	KeyGenDates  KeyGenDates
}

type AID struct {
	RID          [5]byte
	App          byte
	Version      [2]byte
	Manufacturer [2]byte
	Serial       [4]byte
	RFU          [2]byte
}

type AlgoAttr struct {
	ID              byte
	RSAModLen       [2]byte
	RSAPubKeyExpLen [2]byte
	ECurveOID       []byte
	PrivKeyImpFmt   byte
}

type PWStatus struct {
	PW1Validity   byte
	PW1MaxLenFmt  byte
	PW1MaxLenRC   byte
	PW3MaxLenFmt  byte
	PW1RetryCtr   byte
	PW1RCRetryCtr byte
	PW3RetryCtr   byte
}

type Fingerprints struct {
	Sign [20]byte
	Enc  [20]byte
	Auth [20]byte
}

type KeyGenDates struct {
	Sign [4]byte
	Enc  [4]byte
	Auth [4]byte
}

var yubikeyReaderID = "Yubico YubiKey OTP+FIDO+CCID"

func waitUntilCardPresent(ctx *scard.Context, readers []string) (int, error) {
	rs := make([]scard.ReaderState, len(readers))
	for i := range rs {
		rs[i].Reader = readers[i]
		rs[i].CurrentState = scard.StateUnaware
	}

	for {
		for i := range rs {
			if rs[i].EventState&scard.StatePresent != 0 {
				return i, nil
			}
			rs[i].CurrentState = rs[i].EventState
		}
		err := ctx.GetStatusChange(rs, -1)
		if err != nil {
			return -1, err
		}
	}
}

func SelectApp(card *scard.Card) error {
	ca := commandAPDU{
		cla:  0,
		ins:  0xa4,
		p1:   0x04,
		p2:   0,
		data: appID,
		le:   0,
	}

	fmt.Println("\U0001F4E6 Selecting OpenPGP application")

	ra, err := ca.transmit(card)
	if err != nil {
		return err
	}

	if !ra.checkSuccess() {
		return errors.New("This YubiKey does not support OpenPGP")
	}

	return nil
}

func GetData(card *scard.Card, do DataObject) ([]byte, error) {
	data := []byte{}

	ca := commandAPDU{
		cla: 0,
		ins: 0xca,
		p1:  do.tagP1(),
		p2:  do.tagP2(),
		le:  0,
	}

	ra, err := ca.transmit(card)
	if err != nil {
		return nil, err
	}

	data = append(data, ra.data...)

	for !ra.checkSuccess() {
		if ra.sw1 == 0x61 {
			ca = commandAPDU{
				cla: 0,
				ins: 0xc0,
				p1:  0,
				p2:  0,
				le:  0,
			}

			ra, err = ca.transmit(card)
			if err != nil {
				return nil, err
			}

			data = append(data, ra.data...)
		} else {
			return nil, errors.New("An error occurred, could not get data segment")
		}
	}

	return data, nil
}

func promptPIN() ([]byte, error) {
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

func getPINRetries(card *scard.Card) (int, error) {
	data, err := GetData(card, doPWStatus)
	if err != nil {
		return 0, err
	}

	return int(data[4]), nil
}

// Verify PIN to allow access to restricted operations, prompt if PIN empty
func Verify(card *scard.Card, pin []byte) error {
	// prompt user if PIN argument is empty
	if bytes.Equal(pin, []byte{}) {
		p, err := promptPIN()
		if err != nil {
			return err
		}

		pin = p
	}

	ca := commandAPDU{
		cla:  0,
		ins:  0x20,
		p1:   0,
		p2:   0x82,
		data: pin,
		le:   0,
	}

	fmt.Println("\U0001F522 Verifying card PIN")

	ra, err := ca.transmit(card)
	if err != nil {
		return err
	}

	if !ra.checkSuccess() {
		retries, err := getPINRetries(card)
		if err != nil {
			return err
		}

		verb := "retry"
		if retries > 1 {
			verb = "retries"
		}

		return fmt.Errorf("Invalid PIN, %d %s remaining", retries, verb)
	}

	return nil
}

func GetAppRelatedData(card *scard.Card) (AppRelatedData, error) {
	var ard AppRelatedData
	data, err := GetData(card, doAppRelData)
	if err != nil {
		return AppRelatedData{}, err
	}

	for _, c := range doAppRelData.getChildren() {
		cData := doFindTLV(data, c.tag, 1)
		buf := bytes.NewReader(cData)

		switch c.tag {
		case doAID.tag:
			ard.AID, err = readAID(buf)
		case doAlgoAttrSign.tag:
			ard.AlgoAttrSign, err = readAlgoAttr(buf)
		case doAlgoAttrEnc.tag:
			ard.AlgoAttrEnc, err = readAlgoAttr(buf)
		case doAlgoAttrAuth.tag:
			ard.AlgoAttrAuth, err = readAlgoAttr(buf)
		case doPWStatus.tag:
			ard.PWStatus, err = readPWStatus(buf)
		case doFingerprints.tag:
			ard.Fingerprints, err = readFingerprints(buf)
		case doKeyGenDate.tag:
			ard.KeyGenDates, err = readKeyGenDates(buf)
		}

		if err != nil {
			return AppRelatedData{}, err
		}
	}

	return ard, nil
}

func readAID(buf *bytes.Reader) (AID, error) {
	var aid AID

	if err := binary.Read(buf, binary.BigEndian, &aid.RID); err != nil {
		return AID{}, err
	}
	if err := binary.Read(buf, binary.BigEndian, &aid.App); err != nil {
		return AID{}, err
	}
	for _, a := range []*[2]byte{&aid.Version, &aid.Manufacturer} {
		if err := binary.Read(buf, binary.BigEndian, a); err != nil {
			return AID{}, err
		}
	}
	if err := binary.Read(buf, binary.BigEndian, &aid.Serial); err != nil {
		return AID{}, err
	}
	if err := binary.Read(buf, binary.BigEndian, &aid.RFU); err != nil {
		return AID{}, err
	}

	return aid, nil
}

func readAlgoAttr(buf *bytes.Reader) (AlgoAttr, error) {
	var aa AlgoAttr

	if err := binary.Read(buf, binary.BigEndian, &aa.ID); err != nil {
		return AlgoAttr{}, err
	}

	switch aa.ID {
	case AlgoIdRSA:
		for _, a := range []*[2]byte{&aa.RSAModLen, &aa.RSAPubKeyExpLen} {
			if err := binary.Read(buf, binary.BigEndian, a); err != nil {
				return AlgoAttr{}, err
			}
		}
	case AlgoIdECDH, AlgoIdECDSA:
		aa.ECurveOID = make([]byte, buf.Len()-1)
		if err := binary.Read(buf, binary.BigEndian, &aa.ECurveOID); err != nil {
			return AlgoAttr{}, err
		}

	}

	if err := binary.Read(buf, binary.BigEndian, &aa.PrivKeyImpFmt); err != nil {
		return AlgoAttr{}, err
	}

	return aa, nil
}

func readPWStatus(buf *bytes.Reader) (PWStatus, error) {
	var pws PWStatus
	pwb := []*byte{&pws.PW1Validity, &pws.PW1MaxLenFmt, &pws.PW1MaxLenRC,
		&pws.PW3MaxLenFmt, &pws.PW1RetryCtr, &pws.PW1RCRetryCtr, &pws.PW3RetryCtr}

	for _, p := range pwb {
		if err := binary.Read(buf, binary.BigEndian, p); err != nil {
			return PWStatus{}, err
		}
	}

	return pws, nil
}

func readFingerprints(buf *bytes.Reader) (Fingerprints, error) {
	var fps Fingerprints

	for _, fp := range []*[20]byte{&fps.Sign, &fps.Enc, &fps.Auth} {
		if err := binary.Read(buf, binary.BigEndian, fp); err != nil {
			return Fingerprints{}, err
		}
	}

	return fps, nil
}

func readKeyGenDates(buf *bytes.Reader) (KeyGenDates, error) {
	var kgds KeyGenDates

	for _, kgd := range []*[4]byte{&kgds.Sign, &kgds.Enc, &kgds.Auth} {
		if err := binary.Read(buf, binary.BigEndian, kgd); err != nil {
			return KeyGenDates{}, err
		}
	}

	return kgds, nil
}

// Decipher data with private key on smart card
func Decipher(card *scard.Card, data []byte) ([]byte, error) {
	ca := commandAPDU{
		cla:  0,
		ins:  0x2a,
		p1:   0x80,
		p2:   0x86,
		data: append([]byte{0}, data...), // prepend RSA padding indicator byte
		le:   0,
		pib:  true,
		elf:  true,
	}

	// verify PIN
	err := Verify(card, []byte{})
	if err != nil {
		return nil, err
	}

	ra, err := ca.transmit(card)
	if err != nil {
		return nil, err
	}

	if !ra.checkSuccess() || len(ra.data) != 19 {
		return nil, errors.New("Unable to decipher PGP session key")
	}

	key := ra.data[1 : len(ra.data)-2]
	return key, nil
}

// ConnectYubiKeys establishes the system context and opens sessions with all available smart card readers
func (yk *YubiKey) Connect() error {
	// Establish a context
	ctx, err := scard.EstablishContext()
	if err != nil {
		return err
	}

	yk.Context = ctx

	// List available readers
	readers, err := ctx.ListReaders()
	if err != nil {
		return err
	}

	// Ignore other smart cards
	var yks []string
	for _, r := range readers {
		if strings.HasPrefix(r, yubikeyReaderID) {
			yks = append(yks, r)
		}
	}

	if len(yks) > 0 {
		// wait for card
		fmt.Println("\u23F3 Waiting for a Yubico YubiKey")
		i, err := waitUntilCardPresent(ctx, yks)
		if err != nil {
			return err
		}

		// Connect to card
		fmt.Println("\u26A1 Connecting to", yks[i])
		card, err := ctx.Connect(yks[i], scard.ShareExclusive, scard.ProtocolAny)
		if err != nil {
			return err
		}

		// if card supports OpenPGP applet, select application, and add it to cards
		if err = SelectApp(card); err == nil {
			yk.Card = card
		}
	} else {
		return errors.New("No YubiKeys found")
	}

	return nil
}

// DisconnectYubiKeys disconnects all open sessions smart cards and
// releases the system context
func (yk *YubiKey) Disconnect() error {
	// Disconnect cards by sending reset command
	err := yk.Card.Disconnect(scard.ResetCard)
	if err != nil {
		return err
	}

	// Release reader context
	err = yk.Context.Release()
	if err != nil {
		return err
	}

	return nil
}
