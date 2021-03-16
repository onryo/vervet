package yubikeyscard

import (
	"encoding/binary"
	"errors"
)

const (
	MaxResponseLength uint16 = 256
)

type DataObject struct {
	tag         uint16
	constructed bool
	parent      uint16
	binary      bool
	extLen      uint8
	desc        string
}

var doURL = DataObject{tag: 0x5F50, constructed: false, parent: 0, binary: false, extLen: 2, desc: "URL"}
var doHistBytes = DataObject{tag: 0x5F52, constructed: false, parent: 0, binary: true, extLen: 0, desc: "Historical Bytes"}
var doCardRelData = DataObject{tag: 0x0065, constructed: true, parent: 0, binary: true, extLen: 0, desc: "Cardholder Related Data"}
var doName = DataObject{tag: 0x005B, constructed: false, parent: 0x65, binary: false, extLen: 0, desc: "Name"}
var doLangPrefs = DataObject{tag: 0x5F2D, constructed: false, parent: 0x65, binary: false, extLen: 0, desc: "Language preferences"}
var doAppRelData = DataObject{tag: 0x006E, constructed: true, parent: 0, binary: true, extLen: 0, desc: "Application Related Data"}
var doLoginData = DataObject{tag: 0x005E, constructed: false, parent: 0, binary: true, extLen: 2, desc: "Login Data"}
var doAppID = DataObject{tag: 0x004F, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Application Idenfifier (AID)"}
var doDiscrDOs = DataObject{tag: 0x0073, constructed: true, parent: 0, binary: true, extLen: 0, desc: "Discretionary Data Objects"}
var doCardCaps = DataObject{tag: 0x0047, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Card Capabilities"}
var doExtLenCaps = DataObject{tag: 0x00C0, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Extended Card Capabilities"}
var doAlgoAttrSig = DataObject{tag: 0x00C1, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Algorithm Attributes Signature"}
var doAlgoAttrDec = DataObject{tag: 0x00C2, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Algorithm Attributes Decryption"}
var doAlgoAttrAut = DataObject{tag: 0x00C3, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Algorithm Attributes Authentication"}
var doPWStatus = DataObject{tag: 0x00C4, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Password Status Bytes"}
var doFingerprints = DataObject{tag: 0x00C5, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Fingerprints"}
var doCAFingerprints = DataObject{tag: 0x00C6, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "CA Fingerprints"}
var doKeyGenDate = DataObject{tag: 0x00CD, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Generation times of key pairs"}
var doSecSuppTmpl = DataObject{tag: 0x007A, constructed: true, parent: 0, binary: true, extLen: 0, desc: "Security Support Template"}
var doDigSigCtr = DataObject{tag: 0x0093, constructed: false, parent: 0x7A, binary: true, extLen: 0, desc: "Digital Signature Counter"}
var doPrivateDO1 = DataObject{tag: 0x0101, constructed: false, parent: 0, binary: false, extLen: 2, desc: "Private DO 1"}
var doPrivateDO2 = DataObject{tag: 0x0102, constructed: false, parent: 0, binary: false, extLen: 2, desc: "Private DO 2"}
var doPrivateDO3 = DataObject{tag: 0x0103, constructed: false, parent: 0, binary: false, extLen: 2, desc: "Private DO 3"}
var doPrivateDO4 = DataObject{tag: 0x0104, constructed: false, parent: 0, binary: false, extLen: 2, desc: "Private DO 4"}
var doCardholderCrt = DataObject{tag: 0x7F21, constructed: true, parent: 0, binary: true, extLen: 1, desc: "Cardholder certificate"}

// V3.0
var doGenFeatMgmt = DataObject{tag: 0x7F74, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "General Feature Management"}
var doAESKeyData = DataObject{tag: 0x00D5, constructed: false, parent: 0, binary: true, extLen: 0, desc: "AES key data"}
var doUIFSig = DataObject{tag: 0x00D6, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "UIF for Signature"}
var doUIFDec = DataObject{tag: 0x00D7, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "UIF for Decryption"}
var doUIFAut = DataObject{tag: 0x00D8, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "UIF for Authentication"}
var doUIFAtt = DataObject{tag: 0x00D8, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "UIF for Yubico Attestation key"}
var doKDFDO = DataObject{tag: 0x00F9, constructed: false, parent: 0, binary: true, extLen: 0, desc: "KDF data object"}
var doAlgoInfo = DataObject{tag: 0x00FA, constructed: false, parent: 0, binary: true, extLen: 2, desc: "Algorithm Information"}

var DataObjects = []DataObject{
	doURL, doHistBytes, doCardRelData, doName, doLangPrefs, doAppRelData,
	doLoginData, doAppID, doDiscrDOs, doCardCaps, doExtLenCaps, doAlgoAttrSig,
	doAlgoAttrDec, doAlgoAttrAut, doPWStatus, doFingerprints, doCAFingerprints,
	doKeyGenDate, doSecSuppTmpl, doDigSigCtr, doPrivateDO1, doPrivateDO2,
	doPrivateDO3, doPrivateDO4, doCardholderCrt, doGenFeatMgmt, doAESKeyData,
	doUIFSig, doUIFDec, doUIFAut, doUIFAtt, doKDFDO, doAlgoInfo,
}

func (do DataObject) tagBytes() []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(do.tag))
	return b
}

func (do DataObject) tagP1() byte {
	return do.tagBytes()[0]
}

func (do DataObject) tagP2() byte {
	return do.tagBytes()[1]
}

// static const unsigned char *
// do_find_tlv (const unsigned char *buffer, size_t length,
//  int tag, size_t *nbytes, int nestlevel)

func doFindTLV(data []byte, tag uint16, nestLevel int) ([]byte, error) {
	//   const unsigned char *s = buffer;
	//   size_t n = length;
	//   size_t len;
	//   int this_tag;
	//   int composite;

	var o int = 0
	var n int = len(data)
	var tagLen uint16
	var thisTag uint16
	var composite bool

	for true {
		if n < 2 { // Buffer definitely too short for tag and length.
			return nil, errors.New("No data present in buffer")
		}

		if data[o] == 0 || data[o] == 0xff { // Skip optional filler between TLV objects.
			o++
			n--
		}

		composite = (data[o] & 0x20) != 0

		if (data[o] & 0x1f) == 0x1f { // more tag bytes to follow
			o++
			n--

			if n < 2 { // Buffer definitely too short for tag and length.
				return nil, errors.New("No data present in buffer")
			}
			if (data[o] & 0x1f) == 0x1f { // We support only up to 2 bytes.
				return nil, errors.New("Supports only up to 2 bytes")
			}

			thisTag = binary.BigEndian.Uint16([]byte{data[o-1], data[o] & 0x7f})
		} else {
			thisTag = binary.BigEndian.Uint16([]byte{0, data[o]})
		}

		tagLen = binary.BigEndian.Uint16([]byte{0, data[o+1]})
		o += 2
		n -= 2
		if tagLen < 0x80 {
			// do nothing
		} else if tagLen == 0x81 { // One byte length follows.
			if n != 0 { // we expected 1 more bytes with the length
				return nil, errors.New("Expected 1 more bytes with the length")
			}

			tagLen = binary.BigEndian.Uint16([]byte{0, data[o]})
			o++
			n--
		} else if tagLen == 0x82 { // Two byte length follows
			if n < 2 { // We expected 2 more bytes with the length.
				return nil, errors.New("Expected 2 more bytes with the length")
			}

			tagLen = binary.BigEndian.Uint16([]byte{data[o], data[o+1]})
			o += 2
			n -= 2
		} else { // APDU limit is 65535, thus it does not make sense to assume longer length fields. */
			return nil, errors.New("APDU limit is 65535, thus it does not make sense to assume longer length fields")
		}

		if composite && nestLevel < 100 { // Dive into this composite DO after checking for a too deep nesting
			tmpData, err := doFindTLV(data[o:], tag, nestLevel+1)
			if err != nil {
				return nil, err
			}

			if len(tmpData) > 0 {
				return tmpData, nil
			}
		}

		if thisTag == tag {
			return data[o : o+int(tagLen)], nil
		}
		if int(tagLen) > n { // Buffer too short to skip to the next tag.
			return nil, errors.New("Buffer too short to skip to the next tag")
		}

		o += int(tagLen)
		n -= int(tagLen)
	}

	return data[o : o+int(tagLen)], nil
}
