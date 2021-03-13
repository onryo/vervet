package yubikeyscard

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Padding indicator byte values
const (
	pibNone = 0xff
	pibRSA  = 0
	pibAES  = 2
)

// commandAPDU represents an application data unit sent to a smartcard.
type commandAPDU struct {
	cla, ins, p1, p2 uint8  // Class, Instruction, Parameter 1, Parameter 2
	data             []byte // Command data
	le               uint8  // Command data length
	pib              bool   // Padding indicator byte present
	elf              bool   // Use extended length fields
}

// serialize serializes a command APDU.
func (ca commandAPDU) serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// write 4 header bytes to buffer
	if err := binary.Write(buf, binary.BigEndian, []byte{ca.cla, ca.ins, ca.p1, ca.p2}); err != nil {
		return nil, err
	}

	// if a payload exists, calculate the length, prepend it to the payload, and write to buffer
	if len(ca.data) > 0 {
		l := len(ca.data)

		// subtract one byte from length if padding indicator byte present
		if ca.pib {
			l--
		}

		// check if extended length fields (3 bytes) should be used
		if ca.elf {
			lc := make([]byte, 2)
			binary.BigEndian.PutUint16(lc, uint16(l))

			if err := binary.Write(buf, binary.BigEndian, append([]byte{0}, lc...)); err != nil {
				return nil, err
			}
		} else {
			if err := binary.Write(buf, binary.BigEndian, uint8(l)); err != nil {
				return nil, err
			}
		}

		if err := binary.Write(buf, binary.BigEndian, ca.data); err != nil {
			return nil, err
		}
	}

	if err := binary.Write(buf, binary.BigEndian, ca.le); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// responseAPDU represents an application data unit received from a smart card.
type responseAPDU struct {
	Data     []byte // response data
	Sw1, Sw2 uint8  // status words 1 and 2
}

// deserialize deserializes a response APDU.
func (ra *responseAPDU) deserialize(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("can not deserialize data: payload too short (%d < 2)", len(data))
	}

	ra.Data = make([]byte, len(data)-2)

	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.BigEndian, &ra.Data); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &ra.Sw1); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &ra.Sw2); err != nil {
		return err
	}
	return nil
}
