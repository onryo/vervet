package yubikeyscard

import (
	"encoding/binary"
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

type AppRelatedData struct {
	AppID          []byte // Application idenfifier (AID)
	Hist           []byte // Historical bytes
	ExtLen         []byte //Extended length information
	GenFeatMgmt    []byte //General feature management
	DiscrDOs       []byte // Discretionary data objects
	ExtCapFlags    []byte // Extended capabilities flag list
	AlgoAttrSig    []byte // Algorithm attributes signature
	AlgoAttrDec    []byte // Algorithm attributes decryption
	AlgoAttrAut    []byte // Algorithm attributes authentication
	PWStatus       []byte // Password status bytes
	Fingerprints   []byte // Fingerprints
	CAFingerprints []byte // CA fingerprints
	keyGenDate     []byte // List of generation dates/times of key pairs
	keyInfo        []byte // Key information
	uifSig         []byte // User Interaction Flag (UIF) for PSO:CDS (optional)
	uifDec         []byte // UIF for PSO:DEC (optional)
	uifAut         []byte // UIF for PSO:AUT (optional)
	uifAtt         []byte // Reserved for UIF for Yubico Attestation key (optional)
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
	return do.tagBytes()[0]
}
