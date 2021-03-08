package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ebfe/scard"
)

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

func readSessionKey(cipherTxt []byte, cardPIN []byte) []byte {
	// Establish a context
	ctx, err := scard.EstablishContext()
	if err != nil {
		die(err)
	}
	defer ctx.Release()

	// List available readers
	readers, err := ctx.ListReaders()
	if err != nil {
		die(err)
	}

	var sessionKey []byte

	if len(readers) > 0 {
		// wait for card
		fmt.Println("\u23F3 Waiting for a Yubico YubiKey")
		index, err := waitUntilCardPresent(ctx, readers)
		if err != nil {
			die(err)
		}

		// Connect to card
		fmt.Println("\u26A1 Connecting to", readers[index])
		card, err := ctx.Connect(readers[index], scard.ShareExclusive, scard.ProtocolAny)
		if err != nil {
			die(err)
		}
		defer card.Disconnect(scard.ResetCard)

		// select application
		var cmd = []byte{0x00, 0xa4, 0x04, 0x00, 0x06, 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00}
		fmt.Println("\U0001F4E6 Selecting OpenPGP application")
		_, err = card.Transmit(cmd)
		if err != nil {
			die(err)
		}

		// verify pin
		var verifyCmdPre = []byte{0x00, 0x20, 0x00, 0x82, 0x06}
		verifyCmd := append(verifyCmdPre, cardPIN...)
		fmt.Println("\U0001F522 Verifying card PIN")
		verifyRsp, err := card.Transmit(verifyCmd)
		if err != nil {
			die(err)
		}

		if bytes.Compare(verifyRsp, []byte{0x90, 0x00}) != 0 {
			die(errors.New("Invalid PIN"))
		}

		// decrypt data
		cipherTxtBlk := cipherTxt[15:272]

		var cipherTxtBlkLen = make([]byte, 2)
		binary.BigEndian.PutUint16(cipherTxtBlkLen, uint16(len(cipherTxtBlk)))

		var decryptCmdPre = []byte{0x00, 0x2a, 0x80, 0x86, 0x00}
		decryptCmd := append(decryptCmdPre, cipherTxtBlkLen...)
		decryptCmd = append(decryptCmd, 0x00)
		decryptCmd = append(decryptCmd, cipherTxtBlk...)
		decryptCmd = append(decryptCmd, 0x00)

		decryptRsp, err := card.Transmit(decryptCmd)
		if err != nil {
			die(err)
		}

		if len(decryptRsp) == 21 {
			sessionKey = decryptRsp[1 : len(decryptRsp)-4]
		}
	}

	return sessionKey
}
