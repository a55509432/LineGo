package linego

import (
	"bytes"
)


func In(x int, slice []int) bool {
    for _, v := range slice {
        if v == x {
            return true
        }
    }
    return false
}

func BytesCombine(pbytes ...[]byte) []byte {
	length := len(pbytes)
	s := make([][]byte,length)

	for index :=0; index < length; index++ {
		s[index] = pbytes[index]
	}

	sep := []byte("")

	return bytes.Join(s, sep)
}

