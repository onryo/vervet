package vervet

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const maxKeyFileSize int64 = 8192

//
func readFile(path string) ([]byte, error) {
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

	if fileStat.Size() > maxKeyFileSize {
		return nil, fmt.Errorf("unseal key is larger that the maximum file size of %d bytes", maxKeyFileSize)
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
