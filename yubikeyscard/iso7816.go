package yubikeyscard

import (
	"errors"
	"fmt"

	"github.com/ebfe/scard"
)

// Decipher data with private key on smart card
func Decipher(card *scard.Card, data []byte) ([]byte, error) {
	ca := commandAPDU{
		cla:  0,
		ins:  0x2a,
		p1:   0x80,
		p2:   0x86,
		data: append(append([]byte{0}, data...), 1), // prepend RSA padding indicator byte and append footer
		le:   0,
		pib:  true,
		elf:  true,
	}

	if len(data)%16 != 0 {
		return nil, errors.New("decipher input blocks should be in multiples of 16 bytes")
	}

	ra, err := ca.transmit(card)
	if err != nil {
		return nil, err
	}

	if !ra.checkSuccess() {
		return nil, errors.New("decipher operation unsuccessful")
	}

	return ra.data, nil
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
			return nil, errors.New("error occurred, could not get data segment")
		}
	}

	return data, nil
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

	ra, err := ca.transmit(card)
	if err != nil {
		return err
	}

	if !ra.checkSuccess() {
		return errors.New("this YubiKey does not support OpenPGP")
	}

	return nil
}

// Verify PIN to allow access to restricted operations, prompt if PIN empty
func Verify(card *scard.Card, pin []byte) error {
	ca := commandAPDU{
		cla:  0,
		ins:  0x20,
		p1:   0,
		p2:   0x82,
		data: pin,
		le:   0,
	}

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

		return fmt.Errorf("invalid PIN, %d %s remaining", retries, verb)
	}

	return nil
}
