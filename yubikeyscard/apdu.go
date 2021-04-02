package yubikeyscard

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ebfe/scard"
)

var appID = []byte{0xd2, 0x76, 0x00, 0x01, 0x24, 0x01} // OpenPGP applet ID

// commandAPDU represents an application data unit sent to a smartcard.
type commandAPDU struct {
	cla, ins, p1, p2 uint8  // Class, Instruction, Parameter 1, Parameter 2
	data             []byte // Command data
	le               uint8  // Command data length
	pib              bool   // Padding indicator byte present
	elf              bool   // Use extended length fields
}

// responseAPDU represents an application data unit received from a smart card.
type responseAPDU struct {
	data     []byte // response data
	sw1, sw2 uint8  // status words 1 and 2
}

// serialize serializes a command APDU.
func (ca commandAPDU) serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// write 4 header bytes to buffer
	if _, err := buf.Write([]byte{ca.cla, ca.ins, ca.p1, ca.p2}); err != nil {
		return nil, err
	}

	// if a payload exists, calculate the length, prepend it to the payload, and write to buffer
	if len(ca.data) > 0 {
		lc := len(ca.data)

		// subtract one byte from length if padding indicator byte present
		if ca.pib {
			lc--
		}

		// check if extended length fields (3 bytes) should be used
		if ca.elf {
			lcElf := make([]byte, 2)
			binary.BigEndian.PutUint16(lcElf, uint16(lc))

			if _, err := buf.Write(append([]byte{0}, lcElf...)); err != nil {
				return nil, err
			}
		} else {
			if _, err := buf.Write([]byte{uint8(lc)}); err != nil {
				return nil, err
			}
		}

		if _, err := buf.Write(ca.data); err != nil {
			return nil, err
		}
	}

	if _, err := buf.Write([]byte{ca.le}); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// transmit will send the serialized APDU command to the applet.
func (ca commandAPDU) transmit(card *scard.Card) (responseAPDU, error) {
	ra := new(responseAPDU)

	cmd, err := ca.serialize()
	if err != nil {
		return *ra, err
	}

	rsp, err := card.Transmit(cmd)
	if err != nil {
		return *ra, err
	}

	if err = ra.deserialize(rsp); err != nil {
		return *ra, err
	}

	return *ra, nil
}

// deserialize deserializes a response APDU.
func (ra *responseAPDU) deserialize(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("can not deserialize data: payload too short (%d < 2)", len(data))
	}

	r := bytes.NewReader(data)

	ra.data = make([]byte, len(data)-2)
	_, err := io.ReadFull(r, ra.data)
	if err != nil {
		return err
	}

	sw := make([]byte, 2)
	_, err = io.ReadFull(r, sw)
	if err != nil {
		return err
	}

	ra.sw1 = sw[0]
	ra.sw2 = sw[1]

	return nil
}

func (ra *responseAPDU) success() bool {
	success := []byte{0x90, 0x00}
	status := []byte{ra.sw1, ra.sw2}

	return bytes.Equal(status, success)
}
