package tictac

import (
	"bytes"
	"fmt"
	"io"
)

const DEFAULT_PORT = 49

const (
	headerLen               = 12 // 96 bits
	authenStartHeaderLen    = 8  // 64 bits
	authenReplyHeaderLen    = 6  // 48 bits
	authenContinueHeaderLen = 5  // 40 bits

	maxUint8  = 256
	maxUint16 = 65536
	maxUint32 = 4294967296
)

// Header major_version
const (
	TAC_PLUS_MAJOR_VER = 0xc
)

// Header minor_verison
const (
	TAC_PLUS_MINOR_VER_DEFAULT = 0x0
	TAC_PLUS_MINOR_VER_ONE     = 0x1
)

// Header type
const (
	TAC_PLUS_AUTHEN = 0x1 // Authentication
	TAC_PLUS_AUTHOR = 0x2 // Authorization
	TAC_PLUS_ACCT   = 0x3 // Accounting
)

// Header flags
const (
	TAC_PLUS_UNENCRYPTED_FLAG    = 1 << 1
	TAC_PLUS_SINGLE_CONNECT_FLAG = 1 << 2
)

// AUTHEN START action
const (
	TAC_PLUS_AUTHEN_LOGIN    = 0x1
	TAC_PLUS_AUTHEN_CHPASS   = 0x2
	TAC_PLUS_AUTHEN_SENDPASS = 0x3 // deprecated
	TAC_PLUS_AUTHEN_SENDAUTH = 0x4
)

// AUTHEN START priv_level
const (
	TAC_PLUS_PRIV_LVL_MAX  = 0xf
	TAC_PLUS_PRIV_LVL_ROOT = 0xf
	TAC_PLUS_PRIV_LVL_USER = 0x1
	TAC_PLUS_PRIV_LVL_MIN  = 0x0
)

// AUTHEN START authen_type
const (
	TAC_PLUS_AUTHEN_TYPE_ASCII  = 0x1
	TAC_PLUS_AUTHEN_TYPE_PAP    = 0x2
	TAC_PLUS_AUTHEN_TYPE_CHAP   = 0x3
	TAC_PLUS_AUTHEN_TYPE_ARAP   = 0x4
	TAC_PLUS_AUTHEN_TYPE_MSCHAP = 0x5
)

// AUTHEN START service
const (
	TAC_PLUS_AUTHEN_SVC_NONE    = 0x0
	TAC_PLUS_AUTHEN_SVC_LOGIN   = 0x1
	TAC_PLUS_AUTHEN_SVC_ENABLE  = 0x2
	TAC_PLUS_AUTHEN_SVC_PPP     = 0x3
	TAC_PLUS_AUTHEN_SVC_ARAP    = 0x4
	TAC_PLUS_AUTHEN_SVC_PT      = 0x5
	TAC_PLUS_AUTHEN_SVC_RCMD    = 0x6
	TAC_PLUS_AUTHEN_SVC_X25     = 0x7
	TAC_PLUS_AUTHEN_SVC_NASI    = 0x8
	TAC_PLUS_AUTHEN_SVC_FWPROXY = 0x9
)

// REPLY status
const (
	TAC_PLUS_AUTHEN_STATUS_PASS    = 0x1
	TAC_PLUS_AUTHEN_STATUS_FAIL    = 0x2
	TAC_PLUS_AUTHEN_STATUS_GETDATA = 0x3
	TAC_PLUS_AUTHEN_STATUS_GETUSER = 0x4
	TAC_PLUS_AUTHEN_STATUS_GETPASS = 0x5
	TAC_PLUS_AUTHEN_STATUS_RESTART = 0x6
	TAC_PLUS_AUTHEN_STATUS_ERROR   = 0x7
	TAC_PLUS_AUTHEN_STATUS_FOLLOW  = 0x21
)

// REPLY flags
const (
	TAC_PLUS_REPLY_FLAG_NOECHO = 0x1
)

// CONTINUE flag
const (
	TAC_PLUS_CONTINUE_FLAG_ABORT = 0x1
)

type packetVer uint8

func (v packetVer) minorVersion() uint8 {
	return uint8(v) & 0xf
}

func (v packetVer) majorVersion() uint8 {
	return uint8(v) >> 4
}

func newVersion(minorVer uint8) packetVer {
	return packetVer(TAC_PLUS_MAJOR_VER<<4 + minorVer)
}

const (
	TAC_PLUS_VER_DEFAULT packetVer = TAC_PLUS_MAJOR_VER << 4
	TAC_PLUS_VER_ONE     packetVer = TAC_PLUS_MAJOR_VER<<4 + 1
)

type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) write(b []byte) {
	if ew.err != nil {
		return
	}
	_, ew.err = ew.w.Write(b)
}

type errReader struct {
	r   io.Reader
	err error
}

func (er *errReader) read(n int) []byte {
	if er.err != nil {
		return nil
	}
	v := make([]byte, n)
	_, er.err = io.ReadFull(er.r, v)
	return v
}

// packet represents an entire tacacs packet.  The format is the same for
// both client as well as server
//
//  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |majver | minver |      type      |     seq_no     |     flags      |
// +----------------+----------------+----------------+----------------+
// |                            session_id                             |
// +----------------+----------------+----------------+----------------+
// |                              length                               |
// +----------------+----------------+----------------+----------------+
type packet struct {
	version    packetVer
	packetType uint8
	seq        uint8
	flags      uint8
	sessionID  uint32
	data       []byte
}

func (p *packet) unencrypted() bool {
	return p.flags&TAC_PLUS_UNENCRYPTED_FLAG != 0
}

func (p *packet) singleConn() bool {
	return p.flags&TAC_PLUS_SINGLE_CONNECT_FLAG != 0
}

func (p *packet) serialize(w io.Writer) error {
	if err := checkMsgSize(p.data, maxUint32, "packet.serialize: data"); err != nil {
		return err
	}

	var header [headerLen]byte
	b := writeBuf(header[:])
	b.uint8(uint8(p.version))
	b.uint8(p.packetType)
	b.uint8(p.seq)
	b.uint8(p.flags)
	b.uint32(p.sessionID)
	b.uint32(uint32(len(p.data)))

	ew := errWriter{w: w}
	ew.write(header[:])
	ew.write(p.data)

	return ew.err
}

func (p *packet) parse(r io.Reader) error {
	var header [headerLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}

	// Read in the header information
	b := readBuf(header[:])

	p.version = packetVer(b.uint8())
	if p.version.majorVersion() != TAC_PLUS_MAJOR_VER {
		return fmt.Errorf("Illegal major version specified: found '%d' want '%d",
			p.version.majorVersion(), TAC_PLUS_MAJOR_VER)
	}

	p.packetType = b.uint8()
	p.seq = b.uint8()
	p.flags = b.uint8()
	p.sessionID = b.uint32()
	dataLen := b.uint32()

	er := errReader{r: r}
	// Read the packet body
	p.data = er.read(int(dataLen))

	return er.err

}

// cryptData will encrypt or decrypt the tacplus packet body
func (p *packet) cryptData(key []byte) {
	if p.unencrypted() {
		return
	}

	crypt(p.data, key, uint8(p.version), p.seq, p.sessionID)
	return
}

//  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |    action      |    priv_lvl    |  authen_type   |     service    |
// +----------------+----------------+----------------+----------------+
// |    user len    |    port len    |  rem_addr len  |    data len    |
// +----------------+----------------+----------------+----------------+
// |    user ...
// +----------------+----------------+----------------+----------------+
// |    port ...
// +----------------+----------------+----------------+----------------+
// |    rem_addr ...
// +----------------+----------------+----------------+----------------+
// |    data...
// +----------------+----------------+----------------+----------------+
type authenStart struct {
	action     uint8
	privLvl    uint8
	authenType uint8
	service    uint8
	user       []byte
	port       []byte
	remAddr    []byte
	data       []byte
}

func (s *authenStart) parse(data []byte) error {
	r := bytes.NewReader(data)
	var header [authenStartHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	b := readBuf(header[:])

	s.action = b.uint8()
	s.privLvl = b.uint8()
	s.authenType = b.uint8()
	s.service = b.uint8()
	userLen := b.uint8()
	portLen := b.uint8()
	remAddrLen := b.uint8()
	dataLen := b.uint8()

	if len(data) != int(authenStartHeaderLen+userLen+portLen+remAddrLen+dataLen) {
		return fmt.Errorf("Invalid AUTHEN START packet. Possibly key mismatch")
	}

	er := errReader{r: r}
	s.user = er.read(int(userLen))
	s.port = er.read(int(portLen))
	s.remAddr = er.read(int(remAddrLen))
	s.data = er.read(int(dataLen))

	return er.err
}

func (s *authenStart) serialize() ([]byte, error) {
	if err := checkMsgSize(s.user, maxUint8, "user"); err != nil {
		return nil, err
	}
	if err := checkMsgSize(s.port, maxUint8, "port"); err != nil {
		return nil, err
	}
	if err := checkMsgSize(s.remAddr, maxUint8, "rem_addr"); err != nil {
		return nil, err
	}
	if err := checkMsgSize(s.data, maxUint8, "reply"); err != nil {
		return nil, err
	}

	var w bytes.Buffer
	var header [authenReplyHeaderLen]byte
	b := writeBuf(header[:])
	b.uint8(s.action)
	b.uint8(s.privLvl)
	b.uint8(s.authenType)
	b.uint8(s.service)
	b.uint8(uint8(len(s.user)))
	b.uint8(uint8(len(s.port)))
	b.uint8(uint8(len(s.remAddr)))
	b.uint8(uint8(len(s.data)))

	ew := errWriter{w: &w}

	ew.write(header[:])
	ew.write(s.user)
	ew.write(s.port)
	ew.write(s.remAddr)
	ew.write(s.data)

	return w.Bytes(), ew.err
}

//  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |     status     |      flags     |        server_msg len           |
// +----------------+----------------+----------------+----------------+
// |           data len              |        server_msg ...
// +----------------+----------------+----------------+----------------+
// |           data ...
// +----------------+----------------+
type authenReply struct {
	status    uint8
	flags     uint8
	serverMsg []byte
	data      []byte
}

func (p *authenReply) parse(data []byte) error {
	r := bytes.NewReader(data)
	var header [authenReplyHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	b := readBuf(header[:])

	p.status = b.uint8()
	p.flags = b.uint8()
	serverMsgLen := b.uint16()
	dataLen := b.uint16()

	if len(data) != int(authenReplyHeaderLen+serverMsgLen+dataLen) {
		return fmt.Errorf("Invalid AUTHEN REPLY packet. Possibly key mismatch")
	}

	er := errReader{r: r}
	p.serverMsg = er.read(int(serverMsgLen))
	p.data = er.read(int(dataLen))

	return er.err
}

func (p *authenReply) serialize() ([]byte, error) {
	if err := checkMsgSize(p.serverMsg, maxUint16, "server_msg"); err != nil {
		p.serverMsg = p.serverMsg[:maxUint16]
		fmt.Printf("%s Truncating", err)
	}

	if err := checkMsgSize(p.data, maxUint16, "data"); err != nil {
		return nil, err
	}

	var w bytes.Buffer
	var header [authenReplyHeaderLen]byte
	b := writeBuf(header[:])
	b.uint8(p.status)
	b.uint8(p.flags)
	b.uint16(uint16(len(p.serverMsg)))
	b.uint16(uint16(len(p.data)))

	ew := errWriter{w: &w}
	ew.write(header[:])
	ew.write(p.serverMsg)
	ew.write(p.data)

	return w.Bytes(), ew.err
}

//  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |          user_msg len           |            data len             |
// +----------------+----------------+----------------+----------------+
// |     flags      |  user_msg ...
// +----------------+----------------+----------------+----------------+
// |    data ...
// +----------------+
type authenContinue struct {
	flags   uint8
	userMsg []byte
	data    []byte
}

func (p *authenContinue) parse(data []byte) error {
	r := bytes.NewReader(data)
	var header [authenContinueHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	b := readBuf(header[:])
	userMsgLen := b.uint16()
	dataLen := b.uint16()
	p.flags = b.uint8()

	if len(data) != int(authenContinueHeaderLen+userMsgLen+dataLen) {
		return fmt.Errorf("Invalid AUTHEN CONTINUE packet. Possibly key mismatch")
	}

	er := errReader{r: r}
	p.userMsg = er.read(int(userMsgLen))
	p.data = er.read(int(dataLen))

	return er.err
}

func (p *authenContinue) serialize() ([]byte, error) {
	if err := checkMsgSize(p.userMsg, maxUint16, "user_msg"); err != nil {
		p.userMsg = p.userMsg[:maxUint16]
		fmt.Printf("%s Truncating", err)
	}

	if err := checkMsgSize(p.data, maxUint16, "data"); err != nil {
		return nil, err
	}

	var w bytes.Buffer
	var header [authenContinueHeaderLen]byte
	b := writeBuf(header[:])
	b.uint16(uint16(len(p.userMsg)))
	b.uint16(uint16(len(p.data)))
	b.uint8(p.flags)

	ew := errWriter{w: &w}
	ew.write(header[:])
	ew.write(p.userMsg)
	ew.write(p.data)

	return w.Bytes(), ew.err
}
