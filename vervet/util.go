package vervet

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const keyFileSizeMax int64 = 8192

func ReadKeyFile(path string) ([]string, error) {
	buf, err := readFile(path, keyFileSizeMax)
	if err != nil {
		return nil, err
	}

	return strings.Split(strings.TrimSpace(string(buf)), "\n"), nil
}

// readFile will read a file from the provide path up to the byte length
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

func fmtFingerprint(fp [20]byte) string {
	var fpString string

	for i := 0; i < len(fp); i += 2 {
		fpString = strings.ToUpper(fmt.Sprintf(fpString+"%x ", fp[i:i+2]))
	}

	return strings.TrimSpace(fpString[:24] + " " + fpString[24:])
}
