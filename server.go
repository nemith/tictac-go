package tictac

import (
	"fmt"
	"net"
)

type KeyLookuper interface {
	LookupKey(Peer)
}

// session represents the state of a single tacacs session which is identified
// by the session_id field in the tacacs common header.
type session struct {
	conn      net.Conn
	seq       uint8
	peer 	Net.IP
	sessionId uint32
	key       []byte
}

func NewSession(conn net.Conn) *session {
	return &session{
		conn: conn,
	}
}

func (s *session) Handle() {
	s.peerAddr, _, _ = net.SplitHostPort(s.conn.RemoteAddr().String())
	names, err := net.LookupAddr(s.peerAddr)
	if err != nil {
		fmt.Println("Could not loopup name for address: %s", s.peerAddr)
	}
	s.peerNames = names

	fmt.Printf("New connection from %s (%s)\n", s.peerNames[0], s.peerAddr)

	s.key = []byte("test")

	p := s.readPacket()

	switch p.packetType {
	case TAC_PLUS_AUTHEN:
		handleAuthen()
	case TAC_PLUS_AUTHOR:
	case TAC_PLUS_ACCT:
	default:
		fmt.Printf("Illegal type '%d' in recieved packet", p.packetType)
		return
	}

}

func (s *session) handleAuthen() {
	start := authenStart{}
	if err := start.parse(p.data); err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%#v\n", start)
	fmt.Printf("%v\n", p)
	fmt.Printf("%v\n", start)
	fmt.Printf("%s, %s, %s\n", start.user, start.port, start.remAddr)

	respPacket := s.genPacket(TAC_PLUS_AUTHEN, TAC_PLUS_VER_DEFAULT)
	replyData := authenReply{}
	replyData.status = TAC_PLUS_AUTHEN_STATUS_GETPASS
	twofacMsg := `Assword: `

	replyData.serverMsg = []byte(twofacMsg)
	replyData.data = []byte("")

	respPacket.data, err = replyData.serialize()
	if err != nil {
		fmt.Println(err)
	}
	respPacket.cryptData([]byte("test"))

	fmt.Printf("%#v\n", respPacket)
	fmt.Printf("%#v\n", replyData)

	respPacket.serialize(s.conn)
}

func (s *session) readPacket() *packet {
	p := &packet{}
	if err := p.parse(s.conn); err != nil {
		fmt.Printf("session %s: %s", s.conn.RemoteAddr(), err)
		return nil
	}

	// Go ahead and increment the sequence when we receive a packet
	s.seq = p.seq + 1

	if s.sessionId == 0 {
		// New session, set the session ID
		s.sessionId = p.sessionId
	} else if s.sessionId != p.sessionId {
		fmt.Printf("Invalid session id.  Got '%x', expected '%x,", p.sessionId, s.sessionId)
		return nil
	}

	// Decrypt the data based on the key
	p.cryptData(s.key)

	return p
}

func (s *session) genPacket(packetType uint8, ver packetVer) *packet {
	p := &packet{
		packetType: packetType,
		version:    ver,
		seq:        s.seq,
		sessionId:  s.sessionId,
	}
	return p
}
