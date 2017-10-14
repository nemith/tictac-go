package tictac

import (
	"crypto/md5"
	"encoding/binary"
)

func createHash(version, seq uint8, sessionID uint32, key, lastHash []byte) []byte {
	h := md5.New()
	binary.Write(h, binary.BigEndian, sessionID)
	h.Write(key)
	binary.Write(h, binary.BigEndian, version)
	binary.Write(h, binary.BigEndian, seq)
	h.Write(lastHash)
	return h.Sum(nil)
}

func crypt(data, key []byte, version, seq uint8, sessionID uint32) {
	var lastHash []byte
	for i := 0; i < len(data); i += 16 {
		hash := createHash(version, seq, sessionID, key, lastHash)
		lastHash = hash[:]
		for j := 0; j < len(hash); j++ {
			if i+j < len(data) {
				data[i+j] ^= hash[j]
			} else {
				break
			}
		}
	}
}
