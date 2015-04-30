package tictac

import (
	"encoding/binary"
	"fmt"
)

type writeBuf []byte

func (b *writeBuf) uint8(v uint8) {
	(*b)[0] = byte(v)
	*b = (*b)[1:]
}

func (b *writeBuf) uint16(v uint16) {
	binary.BigEndian.PutUint16(*b, v)
	*b = (*b)[2:]
}

func (b *writeBuf) uint32(v uint32) {
	binary.BigEndian.PutUint32(*b, v)
	*b = (*b)[4:]
}

func (b *writeBuf) uint64(v uint64) {
	binary.BigEndian.PutUint64(*b, v)
	*b = (*b)[8:]
}

type readBuf []byte

func (b *readBuf) uint8() uint8 {
	v := uint8((*b)[0])
	*b = (*b)[1:]
	return v
}

func (b *readBuf) uint16() uint16 {
	v := binary.BigEndian.Uint16(*b)
	*b = (*b)[2:]
	return v
}

func (b *readBuf) uint32() uint32 {
	v := binary.BigEndian.Uint32(*b)
	*b = (*b)[4:]
	return v
}

func (b *readBuf) uint64() uint64 {
	v := binary.BigEndian.Uint64(*b)
	*b = (*b)[8:]
	return v
}

func checkMsgSize(msg []byte, size int, element string) error {
	if len(msg) > size {
		return fmt.Errorf("%s is too big (%d > %d)",
			element, len(msg), size)
	}
	return nil
}
