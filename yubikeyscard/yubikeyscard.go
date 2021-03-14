package yubikeyscard

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/ebfe/scard"
	"golang.org/x/crypto/ssh/terminal"
)

// YubiKeys represents the system context and slice of connected smart cards
type YubiKey struct {
	Context *scard.Context
	Card    *scard.Card
}

const (
	pinMin int = 6
	pinMax int = 127
)

var yubikeyReaderID = "Yubico YubiKey OTP+FIDO+CCID"

var appID = []byte{0xd2, 0x76, 0x00, 0x01, 0x24, 0x01} // OpenPGP applet ID

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

	cmd, err := ca.serialize()
	if err != nil {
		return err
	}

	fmt.Println("\U0001F4E6 Selecting OpenPGP application")

	rsp, err := card.Transmit(cmd)
	if err != nil {
		return err
	}

	ra := new(responseAPDU)
	if err = ra.deserialize(rsp); err != nil {
		return err
	}

	if !ra.checkSuccess() {
		return errors.New("This YubiKey does not support OpenPGP")
	}

	return nil
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

	cmd, err := ca.serialize()
	if err != nil {
		return err
	}

	fmt.Println("\U0001F522 Verifying card PIN")

	rsp, err := card.Transmit(cmd)
	if err != nil {
		return err
	}

	ra := new(responseAPDU)
	if err = ra.deserialize(rsp); err != nil {
		return err
	}

	if !ra.checkSuccess() {
		return errors.New("Invalid PIN")
	}

	return nil
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

	cmd, err := ca.serialize()
	if err != nil {
		return nil, err
	}

	rsp, err := card.Transmit(cmd)
	if err != nil {
		return nil, err
	}

	ra := new(responseAPDU)
	if err = ra.deserialize(rsp); err != nil {
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
