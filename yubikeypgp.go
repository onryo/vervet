package main

import (
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
)

type messageDetails struct {
	IsEncrypted              bool                // true if the message was encrypted.
	EncryptedToKeyIds        []uint64            // the list of recipient key ids.
	IsSymmetricallyEncrypted bool                // true if a passphrase could have decrypted the message.
	DecryptedWith            openpgp.Key         // the private key used to decrypt the message, if any.
	IsSigned                 bool                // true if the message is signed.
	SignedByKeyId            uint64              // the key id of the signer, if any.
	SignedBy                 *openpgp.Key        // the key of the signer, if available.
	LiteralData              *packet.LiteralData // the metadata of the contents
	UnverifiedBody           io.Reader           // the contents of the message.

	// If IsSigned is true and SignedBy is non-zero then the signature will
	// be verified as UnverifiedBody is read. The signature cannot be
	// checked until the whole of UnverifiedBody is read so UnverifiedBody
	// must be consumed until EOF before the data can be trusted. Even if a
	// message isn't signed (or the signer is unknown) the data may contain
	// an authentication code that is only checked once UnverifiedBody has
	// been consumed. Once EOF has been seen, the following fields are
	// valid. (An authentication code failure is reported as a
	// SignatureError error when reading from UnverifiedBody.)
	SignatureError error               // nil if the signature is good.
	Signature      *packet.Signature   // the signature packet itself, if v4 (default)
	SignatureV3    *packet.SignatureV3 // the signature packet if it is a v2 or v3 signature

	decrypted io.ReadCloser
}

func readMessage(r io.Reader, key []byte, cipherFunc packet.CipherFunction) (md *messageDetails, err error) {
	var p packet.Packet

	var se *packet.SymmetricallyEncrypted

	packets := packet.NewReader(r)
	md = new(messageDetails)
	md.IsEncrypted = true

ParsePackets:
	for {
		p, err = packets.Next()
		if err != nil {
			return nil, err
		}

		switch p := p.(type) {

		case *packet.SymmetricallyEncrypted:
			se = p
			break ParsePackets
		}
	}

	var decrypted io.ReadCloser

	decrypted, err = se.Decrypt(cipherFunc, key)
	if err != nil && err != errors.ErrKeyIncorrect {
		return nil, err
	}

	md.decrypted = decrypted
	if err := packets.Push(decrypted); err != nil {
		return nil, err
	}

FindLiteralData:
	for {
		p, err = packets.Next()
		if err != nil {
			return nil, err
		}
		switch p := p.(type) {
		case *packet.LiteralData:
			md.LiteralData = p
			break FindLiteralData
		}
	}

	md.UnverifiedBody = md.LiteralData.Body

	return md, nil
}
