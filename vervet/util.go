package vervet

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
)

const keyFileSizeMax int64 = 8192

const (
	printKVPadWidth     int = 30
	printHeaderPadWidth int = 10
)

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

// PrintKV will bold print the key followed by padding to the specified
// total width, then the value.
func PrintKV(key string, value string) {
	pad := strings.Repeat(".", printKVPadWidth-len(key)-2)
	label := aurora.Bold(fmt.Sprintf("%s %s:", key, pad))
	fmt.Println(label, value)
}

// PrintKV will bold print the key followed by padding to the specified
// total width, then the first value in the slice. If additional values
// are present in the slice they will be displayed on new line indented
// to match the previous value.
func PrintKVSlice(key string, values []string) {
	for i, value := range values {
		if i == 0 {
			pad := strings.Repeat(".", printKVPadWidth-len(key)-2)
			label := aurora.Bold(fmt.Sprintf("%s %s:", key, pad))
			fmt.Println(label, value)
		} else {
			pad := strings.Repeat(" ", printKVPadWidth)
			fmt.Println(pad, value)
		}
	}
}

// PrintHeader will print a bolded header label.
func PrintHeader(label string) {
	pad := strings.Repeat("=", printHeaderPadWidth)
	fmt.Println(aurora.Bold(fmt.Sprintf("%s %s %s", pad, label, pad)))
}

// PrintInfo will print a formatted info message to stdout.
func PrintInfo(msg string) {
	fmt.Println(aurora.Blue(aurora.Bold("[info]   ")), msg)
}

// PrintSuccess will print a formatted success message to stdout.
func PrintSuccess(msg string) {
	fmt.Println(aurora.Green(aurora.Bold("[success]")), msg)
}

// PrintWarning will print a formatted warning message to stdout.
func PrintWarning(msg string) {
	fmt.Println(aurora.Yellow(aurora.Bold("[warning]")), msg)
}

// PrintError will print a formatted error message to stdout.
func PrintError(msg string) {
	fmt.Println(aurora.Red(aurora.Bold("[error]  ")), msg)
}

// PrintFatal will print a formatted error message to stdout and exit with
// the provided status.
func PrintFatal(msg string, code int) {
	fmt.Println(aurora.Red(aurora.Bold("[fatal]  ")), msg)
	os.Exit(code)
}

// Unique is a function that removes duplicate strings from a slice of strings
// and returns the deduplicated slice.
func Unique(orig []string) []string {
	var dedup []string

	for _, s := range orig {
		present := false

		for _, d := range dedup {
			if s == d {
				present = true
				break
			}
		}

		if !present {
			dedup = append(dedup, s)
		}
	}

	return dedup
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

// fmtFingerprintTerse accepts a byte array containing a PGP fingerprint and
// returns a short form formatted string that displays the last 8 bytes of the
// fingerprint in 2-byte hexadecimal blocks.
func fmtFingerprintTerse(fp [20]byte) string {
	var fpString string

	for i := 12; i < len(fp); i += 2 {
		fpString = strings.ToUpper(fmt.Sprintf(fpString+"%x", fp[i:i+2]))
	}

	return fpString
}
