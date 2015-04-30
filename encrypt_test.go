package tictac

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type packetData struct {
	version   packetVer
	seq       uint8
	sessionId uint32
	key       []byte
}

type hashTest struct {
	name     string
	lastHash []byte
	expected string
	packetData
}

var hashTests = []hashTest{
	{"noLastHash", []byte(""), "5ead8a4a8cdbf69831e02cb36f08c979",
		packetData{
			version:   TAC_PLUS_VER_DEFAULT,
			seq:       1,
			sessionId: 1581998937,
			key:       []byte("test"),
		},
	},
	{"withHash", []byte("5ead8a4a8cdbf69831e02cb36f08c979"), "17b76b0789a37b7ba8012927c62e9e68",
		packetData{
			version:   TAC_PLUS_VER_DEFAULT,
			seq:       1,
			sessionId: 1581998937,
			key:       []byte("test"),
		},
	},
}

func TestHash(t *testing.T) {
	for i, test := range hashTests {
		lastHash := make([]byte, hex.DecodedLen(len(test.lastHash)))
		hex.Decode(lastHash, test.lastHash)
		calcHash := createHash(uint8(test.version), test.seq, test.sessionId, test.key, lastHash)
		expectedHash, _ := hex.DecodeString(test.expected)
		if !bytes.Equal(calcHash, expectedHash) {
			t.Errorf("%d %s: expected '%x', got '%x'", i, test.name, expectedHash, calcHash)
		}
	}
}

type cryptTest struct {
	uncryptedData []byte
	cryptedData   []byte
	packetData
}

var cryptTests = []cryptTest{
	{
		[]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur in facilisis metus, in tempor sem."),
		[]byte("12c2f82fe1fb9fe8429541930b67a5166597186efd831a16cd750507a541f01b743c84e6f78135fc4ec6b6766700761c02344b6202e2b70dd4cdd770b2c7072d0dbf1544d96f975c50cafb7c964acbe7fdc2dcc36ec599d5cd4e105b7cd8051aaeda92b1e4"),
		packetData{
			version:   TAC_PLUS_VER_DEFAULT,
			seq:       1,
			sessionId: 1581998937,
			key:       []byte("test"),
		},
	},
}

func TestCrypt(t *testing.T) {
	for _, test := range cryptTests {
		calc := test.uncryptedData[:]
		crypt(calc, test.key, uint8(test.version), test.seq, test.sessionId)
		expected := make([]byte, hex.DecodedLen(len(test.cryptedData)))
		hex.Decode(expected, test.cryptedData)
		if !bytes.Equal(calc, expected) {
			t.Errorf("expected '%s' got '%s'", expected, calc)
		}
	}
}
