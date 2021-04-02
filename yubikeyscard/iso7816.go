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

	if !ra.success() {
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

	for !ra.success() {
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

	if !ra.success() {
		return errors.New("this YubiKey does not support OpenPGP")
	}

	return nil
}

// Verify is used to check the PIN for the provided bank and set appropriate
// access. Verify will return the number of tries remaining. If an error other
// than an invalid PIN occurs, -1 will be returned for the number of remaining
// retries.
func Verify(card *scard.Card, bank uint8, pin []byte) (int, error) {
	ca := commandAPDU{
		cla:  0,
		ins:  0x20,
		p1:   0,
		p2:   0x80 + bank,
		data: pin,
		le:   0,
	}

	if bank < 1 || bank > 3 {
		return -1, errors.New("invalid PIN bank, use banks 1-3")
	}

	ra, err := ca.transmit(card)
	if err != nil {
		return -1, err
	}

	if !ra.success() {
		retries, err := pw1PINRetries(card)
		if err != nil {
			return -1, err
		}

		verb := "retry"
		if retries > 1 {
			verb = "retries"
		}

		return retries, fmt.Errorf("invalid PIN, %d %s remaining", retries, verb)
	}

	return 3, nil
}
