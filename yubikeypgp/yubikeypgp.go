package yubikeypgp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"vervet/yubikeyscard"

	"golang.org/x/crypto/openpgp/packet"
)

const (
	sessionKeyLength                = 16
	encryptedKeyPacketHeaderLength  = 3
	encryptedKeyPacketKeyInfoLength = 12
	symmetricallyEncryptedVersion   = 1
)

type PinPromptFunction func() ([]byte, error)

type encryptedKeyPacket struct {
	tag            uint8
	length         int
	version        uint8
	keyID          uint64
	keyAlgo        uint8
	keySize        uint16
	encryptedBytes []byte
}

// Decrypt will decrypt a PGP-encrypted message by using a YubiKey to first
// obtain the session key (DEK). Decrypt will then decrypt the symmetrically
// encrypted portion of the message and return the resultant plain text.
// In the event of an incorrect PIN, Decrypt will return an empty byte array
// and the number of remaining PIN retries.
func Decrypt(yk *yubikeyscard.YubiKey, cipherTxt []byte, prompt PinPromptFunction) ([]byte, int, error) {
	// read encrypted key packet fields and deserialize to struct
	ek, err := readEncKeyPacket(bytes.NewReader(cipherTxt))
	if err != nil {
		return nil, -1, err
	}

	// verify that YubiKey has the decryption key needed
	if !ykHasKey(yk, ek.keyID) {
		return nil, -1, errors.New("decryption key could not be found on YubiKey")
	}

	// check if PIN is cached, if not retrieve PIN input from user, then validate format
	pin := yk.GetCachedPIN(2)

	if pin == nil {
		pin, err = prompt()
		if err != nil {
			return nil, -1, err
		}
	}

	// verify the PIN (bank 2) with the OpenPGP smart card applet
	retries, err := yubikeyscard.Verify(yk.Card, 2, pin)
	if err != nil {
		return nil, retries, err
	} else {
		// add verified PIN to the cache
		yk.SetCachedPIN(2, pin)
	}

	// decipher the session key
	sk, err := yubikeyscard.Decipher(yk.Card, ek.encryptedBytes)
	if err != nil {
		return nil, retries, err
	}

	if len(sk) != (sessionKeyLength + 3) {
		return nil, retries, errors.New("unable to decipher PGP session key")
	}

	// get cipher function from first octect
	c := packet.CipherFunction(sk[0])
	if c != packet.CipherAES128 {
		return nil, retries, errors.New("unsupported cipher function, only AES-128-CFB supported")
	}

	// after cipher function, the next 16 bytes contain the session key
	sessionKey := sk[1 : sessionKeyLength+1]

	// read the message from the symmetrically encrypted packet using session key
	plainTxt, err := readSymEncPacket(bytes.NewReader(cipherTxt[ek.length:]), sessionKey, c)

	return plainTxt, retries, err
}

func readHeader(r io.Reader) (tag uint8, length int, contents io.Reader, err error) {
	var buf [3]byte

	_, err = io.ReadFull(r, buf[:])
	if err != nil {
		return
	}

	if buf[0]&0xc0 != 0xc0 {
		err = errors.New("invalid PGP packet header, only new format supported")
		return
	}

	if buf[1] < 192 && buf[1] > 223 {
		err = errors.New("invalid PGP packet length, expected two-octect length format")
		return
	}

	tag = buf[0] & 0x1f
	length = int(binary.BigEndian.Uint16([]byte{buf[1] - 192, buf[2]})+192) + 3
	contents = r
	return tag, length, contents, nil
}

func readEncKeyPacket(r io.Reader) (ek encryptedKeyPacket, err error) {
	var buf [encryptedKeyPacketKeyInfoLength]byte

	tag, length, contents, err := readHeader(r)
	if err != nil {
		return
	}

	if tag != 1 {
		return ek, errors.New("invalid PGP packet type, only encrypted key and symmetrically encrypted packets supported")
	}

	n, err := io.ReadFull(contents, buf[:])
	if err != nil {
		return
	}

	if n != encryptedKeyPacketKeyInfoLength {
		return ek, errors.New("invalid PGP packet, body too short")
	}

	if buf[0] != 3 {
		return ek, errors.New("invalid PGP encrypted key packet, only version 3 supported")
	}

	if buf[9] != uint8(packet.PubKeyAlgoRSA) {
		return encryptedKeyPacket{}, errors.New("invalid PGP encrypted key packet, only RSA supported")
	}

	ek.tag = tag
	ek.length = length
	ek.version = buf[0]
	ek.keyID = binary.BigEndian.Uint64(buf[1:9])
	ek.keyAlgo = buf[9]
	ek.keySize = binary.BigEndian.Uint16(buf[10:12])

	ek.encryptedBytes = make([]byte, length-(encryptedKeyPacketHeaderLength+encryptedKeyPacketKeyInfoLength))
	if err = binary.Read(contents, binary.BigEndian, &ek.encryptedBytes); err != nil {
		return
	}

	return ek, nil
}

func readSymEncPacket(r io.Reader, key []byte, cipherFunc packet.CipherFunction) ([]byte, error) {
	packets := packet.NewReader(r)

	for {
		p, err := packets.Next()
		if err != nil {
			return nil, err
		}

		switch p := p.(type) {

		case *packet.SymmetricallyEncrypted:
			decrypted, err := p.Decrypt(cipherFunc, key)
			if err != nil {
				return nil, err
			}

			if err := packets.Push(decrypted); err != nil {
				return nil, err
			}
		case *packet.LiteralData:
			msg, err := io.ReadAll(p.Body)
			if err != nil {
				return nil, err
			}

			return msg, nil
		default:
			return nil, errors.New("unexpected PGP packet type encountered")
		}
	}
}

func ykHasKey(yk *yubikeyscard.YubiKey, keyId uint64) bool {
	fps := yk.AppRelatedData.Fingerprints

	for _, fp := range [][20]byte{fps.Sign, fps.Enc, fps.Auth} {
		if binary.BigEndian.Uint64(fp[12:20]) == keyId {
			return true
		}
	}

	return false
}
