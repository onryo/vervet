package yubikeyscard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/ebfe/scard"
)

const (
	AlgoIdRSA   uint8 = 1
	AlgoIdECDH  uint8 = 12
	AlgoIdECDSA uint8 = 13
)

const (
	scardPresentTimeout         int = 1
	scardGetStatusChangeTimeout int = 5
)

var yubikeyManufacturerID = [2]byte{0, 6}

type YubiKeys struct {
	YubiKeys []*YubiKey
	Context  *scard.Context
}

type YubiKey struct {
	Card            *scard.Card
	ReaderLabel     string
	CardRelatedData CardRelatedData
	AppRelatedData  AppRelatedData
	PINCache        [3][]byte
}

type CardRelatedData struct {
	Name          []byte
	LanguagePrefs []byte
	Salutation    byte
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

func waitUntilCardsPresent(ctx *scard.Context, readers []string) ([]string, error) {
	start := time.Now()
	var presentReaders []string
	rs := make([]scard.ReaderState, len(readers))

	for i := range rs {
		rs[i].Reader = readers[i]
		rs[i].CurrentState = scard.StateUnaware
	}

	for {
		ready := 0
		for i := range rs {
			rs[i].CurrentState = rs[i].EventState
			if rs[i].EventState&scard.StatePresent != 0 {
				ready++

				for _, pr := range presentReaders {
					if pr == readers[i] {
						continue
					}
				}

				presentReaders = append(presentReaders, readers[i])
			}

		}

		if ready == len(readers) {
			return presentReaders, nil
		}

		err := ctx.GetStatusChange(rs, time.Duration(scardPresentTimeout)*time.Second)
		if err != nil {
			return nil, err
		}

		if time.Since(start) > time.Duration(scardGetStatusChangeTimeout)*time.Second {
			return presentReaders, nil
		}
	}
}

func getPINRetries(card *scard.Card) (int, error) {
	data, err := GetData(card, doPWStatus)
	if err != nil {
		return 0, err
	}

	return int(data[4]), nil
}

func GetCardRelatedData(card *scard.Card) (CardRelatedData, error) {
	var crd CardRelatedData
	data, err := GetData(card, doCardRelData)
	if err != nil {
		return CardRelatedData{}, err
	}

	for _, c := range doCardRelData.getChildren() {
		cData := doFindTLV(data, c.tag, 1)
		buf := bytes.NewReader(cData)

		switch c.tag {
		case doName.tag:
			crd.Name = make([]byte, buf.Len())
			if err := binary.Read(buf, binary.BigEndian, &crd.Name); err != nil {
				return CardRelatedData{}, err
			}
		case doLangPrefs.tag:
			crd.LanguagePrefs = make([]byte, buf.Len())
			if err := binary.Read(buf, binary.BigEndian, &crd.LanguagePrefs); err != nil {
				return CardRelatedData{}, err
			}
		case doSalutation.tag:
			if err := binary.Read(buf, binary.BigEndian, &crd.Salutation); err != nil {
				return CardRelatedData{}, err
			}
		}
		if err != nil {
			return CardRelatedData{}, err
		}
	}

	return crd, nil
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

// Connect establishes the system context and opens sessions with all available
// YubiKeys.
func (yks *YubiKeys) Connect() error {
	// establish system context
	ctx, err := scard.EstablishContext()
	if err != nil {
		return err
	}

	yks.Context = ctx

	// list available smart card readers
	readers, err := ctx.ListReaders()
	if err != nil {
		return err
	}

	// wait for all smards card to reach present state
	presentReaders, err := waitUntilCardsPresent(ctx, readers)
	if err != nil {
		return err
	}

	// ignore other smart cards
	for _, r := range presentReaders {
		yk := new(YubiKey)

		// connect to card
		card, err := ctx.Connect(r, scard.ShareExclusive, scard.ProtocolAny)
		if err != nil {
			return err
		}

		// skip smart cards that do not support the OpenPGP applet
		if err = SelectApp(card); err != nil {
			continue
		}

		// build YubiKey struct
		re := regexp.MustCompile("^(.*?) [0-9]{2}$")
		yk.ReaderLabel = re.ReplaceAllString(r, "$1")
		yk.Card = card

		if yk.CardRelatedData, err = GetCardRelatedData(card); err != nil {
			return err
		}

		if yk.AppRelatedData, err = GetAppRelatedData(card); err != nil {
			return err
		}

		// skip smart cards not manufactured by YubiCo
		if yk.AppRelatedData.AID.Manufacturer != yubikeyManufacturerID {
			continue
		}

		yks.YubiKeys = append(yks.YubiKeys, yk)
	}

	// if no YubiKeys are found, release context, and throw error
	if len(yks.YubiKeys) == 0 {
		// Release reader context
		err = ctx.Release()
		if err != nil {
			return err
		}

		return errors.New("no YubiKeys found")
	}

	return nil
}

// Disconnect will reset all open sessions smart cards and release the system
// context.
func (yks *YubiKeys) Disconnect() error {
	for _, yk := range yks.YubiKeys {
		// Disconnect card by sending reset command
		err := yk.Card.Disconnect(scard.ResetCard)
		if err != nil {
			return err
		}
	}

	// Release reader context
	err := yks.Context.Release()
	if err != nil {
		return err
	}

	return nil
}

// FindBySN will search the connected YubiKeys for matching serial numbers and
// if found, will return a pointer to that YubiKey.
func (yks *YubiKeys) FindBySN(sn string) *YubiKey {
	for _, yk := range yks.YubiKeys {
		if sn == fmt.Sprintf("%x", yk.AppRelatedData.AID.Serial) {
			return yk
		}
	}

	return nil
}

// FindByKeyID will search the connected YubiKeys for a matching PGP key ID and
// if found, will return a pointer to that YubiKey.
func (yks *YubiKeys) FindByKeyID(keyID uint64) *YubiKey {
	for _, yk := range yks.YubiKeys {
		fps := yk.AppRelatedData.Fingerprints

		for _, fp := range [][20]byte{fps.Sign, fps.Enc, fps.Auth} {
			if binary.BigEndian.Uint64(fp[12:20]) == keyID {
				return yk
			}
		}

	}

	return nil
}

// GetCachedPIN returns the cached PIN for the provided bank if available. If PIN is not
// cached, GetCachedPIN will return nil.
func (yk *YubiKey) GetCachedPIN(bank uint8) []byte {
	if bank < 1 || bank > 3 {
		return nil
	}

	return yk.PINCache[bank-1]
}

// SetCachedPIN adds a verified PIN to the cache.
func (yk *YubiKey) SetCachedPIN(bank uint8, pin []byte) error {
	if bank < 1 || bank > 3 {
		return errors.New("invalid PIN bank, use banks 1-3")
	}

	yk.PINCache[bank-1] = pin
	return nil
}
