package vervet

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const keyFileSizeMax int64 = 8192

// ReadFile will read an unseal key file from the provided path and return a 
// slice of strings containing base64-encoded PGP-encrypted Vault unseal keys.
func ReadKeyFile(path string) ([]string, error) {
	buf, err := readFile(path, keyFileSizeMax)
	if err != nil {
		return nil, err
	}

	return strings.Split(strings.TrimSpace(string(buf)), "\n"), nil
}

// readFile will read a file from the provided path up to the byte length
// limit provided.
func readFile(path string, maxBytes int64) ([]byte, error) {
	var buf []byte

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	fileStat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if fileStat.Size() > maxBytes {
		return nil, fmt.Errorf("unseal key is larger that the maximum file size of %d bytes", maxBytes)
	}

	buf, err = io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// PrintInfo will print a formatted info message to stdout.
func PrintInfo (msg string) {
	fmt.Println(aurora.Blue(aurora.Bold("[info]"), msg))
}

// PrintSuccess will print a formatted success message to stdout.
func PrintSuccess () {
	fmt.Println(aurora.Green(aurora.Bold("[success]"), msg))
}

// PrintWarning will print a formatted warning message to stdout.
func PrintWarning () {
	fmt.Println(aurora.Yellow(aurora.Bold("[warning]"), msg))
}

// PrintError will print a formatted error message to stdout.
func PrintError () {
	fmt.Println(aurora.Red(aurora.Bold("[error]"), msg))
}

// fmtFingerprint accepts a byte array containing a PGP fingerprint and 
// returns a formatted string that displays the fingerprint in 2-byte 
// hexadecimal blocks.
func fmtFingerprint(fp [20]byte) string {
	var fpString string

	for i := 0; i < len(fp); i += 2 {
		fpString = strings.ToUpper(fmt.Sprintf(fpString+"%x ", fp[i:i+2]))
	}

	return strings.TrimSpace(fpString[:24] + " " + fpString[24:])
}