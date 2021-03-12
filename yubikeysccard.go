package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"

	"github.com/ebfe/scard"
	"golang.org/x/crypto/ssh/terminal"
)

func checkSuccess(rsp []byte) (bool, error) {
	if len(rsp) < 2 {
		return false, errors.New("Invalid response status bytes length")
	}

	success := []byte{0x90, 0x00}
	status := rsp[len(rsp)-2:]

	return bytes.Compare(status, success) == 0, nil
}

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

func selectOpenPGPApp(card *scard.Card) error {
	header := []byte{0x00, 0xa4, 0x04, 0x00}
	app := []byte{0xd2, 0x76, 0x00, 0x01, 0x24, 0x01}
	lc := byte(len(app))
	le := byte(0x00)

	cmd := append(header, lc)
	cmd = append(cmd, app...)
	cmd = append(cmd, le)

	fmt.Println("\U0001F4E6 Selecting OpenPGP application")

	rsp, err := card.Transmit(cmd)
	if err != nil {
		return err
	}

	success, err := checkSuccess(rsp)
	if err != nil {
		return err
	}

	if !success {
		return errors.New("This YubiKey does not support OpenPGP")
	}

	return nil
}

func getPIN() ([]byte, error) {
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

func verifyPIN(card *scard.Card, pin []byte) error {
	header := []byte{0x00, 0x20, 0x00, 0x82}
	lc := byte(len(pin))
	le := byte(0x00)

	cmd := append(header, lc)
	cmd = append(cmd, pin...)
	cmd = append(cmd, le)

	fmt.Println("\U0001F522 Verifying card PIN")

	rsp, err := card.Transmit(cmd)
	if err != nil {
		return err
	}

	success, err := checkSuccess(rsp)
	if err != nil {
		return err
	}

	if !success {
		return errors.New("Invalid PIN")
	}

	return nil
}

func decipherSessionKey(card *scard.Card, data []byte) ([]byte, error) {
	header := []byte{0x00, 0x2a, 0x80, 0x86, 0x00}
	payload := data[15:272]
	lc := make([]byte, 3)
	le := byte(0x00)

	binary.BigEndian.PutUint16(lc, uint16(len(payload)))

	cmd := append(header, lc...)
	cmd = append(cmd, payload...)
	cmd = append(cmd, le)

	rsp, err := card.Transmit(cmd)
	if err != nil {
		die(err)
	}

	success, err := checkSuccess(rsp)
	if err != nil {
		return nil, err
	}

	if !success || len(rsp) != 21 {
		return nil, errors.New("Unable to decipher PGP session key")
	}

	key := rsp[1 : len(rsp)-4]
	return key, nil
}

func readSessionKey(data []byte) ([]byte, error) {
	// Establish a context
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, err
	}
	defer ctx.Release()

	// List available readers
	readers, err := ctx.ListReaders()
	if err != nil {
		return nil, err
	}

	var key []byte

	if len(readers) > 0 {
		// wait for card
		fmt.Println("\u23F3 Waiting for a Yubico YubiKey")
		index, err := waitUntilCardPresent(ctx, readers)
		if err != nil {
			return nil, err
		}

		// Connect to card
		fmt.Println("\u26A1 Connecting to", readers[index])
		card, err := ctx.Connect(readers[index], scard.ShareExclusive, scard.ProtocolAny)
		if err != nil {
			return nil, err
		}
		defer card.Disconnect(scard.ResetCard)

		// select application
		err = selectOpenPGPApp(card)
		if err != nil {
			return nil, err
		}

		pin, err := getPIN()
		if err != nil {
			die(err)
		}

		// verify pin
		err = verifyPIN(card, pin)
		if err != nil {
			return nil, err
		}

		// decrypt data
		key, err = decipherSessionKey(card, data)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("No YubiKeys found")
	}

	return key, nil
}
