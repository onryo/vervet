package yubikeyscard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

		if err = yk.refreshCardRelatedData(); err != nil {
			return err
		}

		if err = yk.refreshAppRelatedData(); err != nil {
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

// CachedPIN returns the cached PIN for the provided bank if available. If PIN is not
// cached, CachedPIN will return nil.
func (yk *YubiKey) CachedPIN(bank uint8) []byte {
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

func pw1PINRetries(card *scard.Card) (int, error) {
	data, err := GetData(card, doPWStatus)
	if err != nil {
		return 0, err
	}

	return int(data[4]), nil
}

func (yk *YubiKey) refreshCardRelatedData() error {
	crd := &yk.CardRelatedData

	data, err := GetData(yk.Card, doCardRelData)
	if err != nil {
		return err
	}

	for _, c := range doCardRelData.children() {
		d := doFindTLV(data, c.tag, 1)
		r := bytes.NewReader(d)

		switch c.tag {
		case doName.tag:
			crd.Name = make([]byte, r.Len())
			if _, err := io.ReadFull(r, crd.Name); err != nil {
				return err
			}
		case doLangPrefs.tag:
			crd.LanguagePrefs = make([]byte, r.Len())
			if _, err := io.ReadFull(r, crd.LanguagePrefs); err != nil {
				return err
			}
		case doSalutation.tag:
			if crd.Salutation, err = r.ReadByte(); err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (yk *YubiKey) refreshAppRelatedData() error {
	ard := &yk.AppRelatedData

	data, err := GetData(yk.Card, doAppRelData)
	if err != nil {
		return err
	}

	for _, c := range doAppRelData.children() {
		cData := doFindTLV(data, c.tag, 1)
		buf := bytes.NewReader(cData)

		switch c.tag {
		case doAID.tag:
			err = ard.AID.deserialize(buf)
		case doAlgoAttrSign.tag:
			err = ard.AlgoAttrSign.deserialize(buf)
		case doAlgoAttrEnc.tag:
			err = ard.AlgoAttrEnc.deserialize(buf)
		case doAlgoAttrAuth.tag:
			err = ard.AlgoAttrAuth.deserialize(buf)
		case doPWStatus.tag:
			err = ard.PWStatus.deserialize(buf)
		case doFingerprints.tag:
			err = ard.Fingerprints.deserialize(buf)
		case doKeyGenDate.tag:
			err = ard.KeyGenDates.deserialize(buf)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (aid *AID) deserialize(r *bytes.Reader) (err error) {
	if _, err = io.ReadFull(r, aid.RID[:]); err != nil {
		return
	}

	if aid.App, err = r.ReadByte(); err != nil {
		return err
	}

	for _, a := range []*[2]byte{&aid.Version, &aid.Manufacturer} {
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return err
		}
	}

	if _, err := io.ReadFull(r, aid.Serial[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, aid.RFU[:]); err != nil {
		return err
	}

	return nil
}

func (aa *AlgoAttr) deserialize(r *bytes.Reader) (err error) {
	if aa.ID, err = r.ReadByte(); err != nil {
		return err
	}

	switch aa.ID {
	case AlgoIdRSA:
		for _, a := range []*[2]byte{&aa.RSAModLen, &aa.RSAPubKeyExpLen} {
			if _, err := io.ReadFull(r, a[:]); err != nil {
				return err
			}
		}
	case AlgoIdECDH, AlgoIdECDSA:
		aa.ECurveOID = make([]byte, r.Len()-1)
		if _, err := io.ReadFull(r, aa.ECurveOID); err != nil {
			return err
		}

	}

	if aa.PrivKeyImpFmt, err = r.ReadByte(); err != nil {
		return err
	}

	return nil
}

func (pws *PWStatus) deserialize(r *bytes.Reader) (err error) {
	pwb := []*byte{&pws.PW1Validity, &pws.PW1MaxLenFmt, &pws.PW1MaxLenRC,
		&pws.PW3MaxLenFmt, &pws.PW1RetryCtr, &pws.PW1RCRetryCtr, &pws.PW3RetryCtr}

	for _, p := range pwb {
		*p, err = r.ReadByte()
		if err != nil {
			return
		}
	}

	return
}

func (fps *Fingerprints) deserialize(r *bytes.Reader) error {
	for _, fp := range []*[20]byte{&fps.Sign, &fps.Enc, &fps.Auth} {
		if _, err := io.ReadFull(r, fp[:]); err != nil {
			return err
		}
	}

	return nil
}

func (kgds *KeyGenDates) deserialize(r *bytes.Reader) error {
	for _, kgd := range []*[4]byte{&kgds.Sign, &kgds.Enc, &kgds.Auth} {
		if _, err := io.ReadFull(r, kgd[:]); err != nil {
			return err
		}
	}

	return nil
}
