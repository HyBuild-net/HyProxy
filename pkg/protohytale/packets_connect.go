package protohytale

import (
	"errors"
	"fmt"
)

// Connect packet constants
const (
	ConnectPacketMinSize = 82 // Minimum size for Connect packet
)

var (
	ErrConnectTooShort = errors.New("connect packet too short")
	ErrInvalidPacketID = errors.New("invalid packet id for this parser")
)

// ConnectPacket represents a parsed Connect packet (0x00000000).
// This is the first packet sent by the client to initiate a connection.
type ConnectPacket struct {
	ProtocolHash  [32]byte // SHA-256 hash identifying protocol version
	ClientType    uint8    // Client type identifier
	UUID          [16]byte // Player UUID (big-endian)
	Language      string   // Client language (e.g., "en_US")
	IdentityToken string   // Identity/auth token
	Username      string   // Player username
	ReferralData  []byte   // Optional referral data
}

// ParseConnect parses a Connect packet from raw data.
func ParseConnect(data []byte) (*ConnectPacket, error) {
	if len(data) < ConnectPacketMinSize {
		return nil, ErrConnectTooShort
	}

	cp := &ConnectPacket{}
	offset := 0

	// Protocol hash (32 bytes)
	copy(cp.ProtocolHash[:], data[offset:offset+32])
	offset += 32

	// Client type (1 byte)
	cp.ClientType = data[offset]
	offset++

	// UUID (16 bytes, big-endian)
	copy(cp.UUID[:], data[offset:offset+16])
	offset += 16

	// Language string (VarInt length + UTF-8)
	if offset >= len(data) {
		return cp, nil // Partial parse OK
	}
	lang, n, err := ReadString(data[offset:])
	if err != nil {
		return cp, nil // Partial parse OK
	}
	cp.Language = lang
	offset += n

	// Identity token string
	if offset >= len(data) {
		return cp, nil
	}
	token, n, err := ReadString(data[offset:])
	if err != nil {
		return cp, nil
	}
	cp.IdentityToken = token
	offset += n

	// Username string
	if offset >= len(data) {
		return cp, nil
	}
	username, n, err := ReadString(data[offset:])
	if err != nil {
		return cp, nil
	}
	cp.Username = username
	offset += n

	// Remaining is referral data
	if offset < len(data) {
		cp.ReferralData = make([]byte, len(data)-offset)
		copy(cp.ReferralData, data[offset:])
	}

	return cp, nil
}

// ParseConnectPacket parses a Connect packet from a Packet struct.
func ParseConnectPacket(p *Packet) (*ConnectPacket, error) {
	if p.ID != PacketConnect {
		return nil, ErrInvalidPacketID
	}
	return ParseConnect(p.Data)
}

// UUIDString returns the UUID as a formatted string.
func (cp *ConnectPacket) UUIDString() string {
	u := cp.UUID
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// ProtocolHashHex returns the protocol hash as a hex string.
func (cp *ConnectPacket) ProtocolHashHex() string {
	return fmt.Sprintf("%x", cp.ProtocolHash)
}

// DisconnectPacket represents a Disconnect packet (0x00000001).
// This packet has no data - just the packet ID signals disconnect.
type DisconnectPacket struct {
	// Reason may be included in some protocol versions
	Reason string
}

// ParseDisconnect parses a Disconnect packet from raw data.
func ParseDisconnect(data []byte) (*DisconnectPacket, error) {
	dp := &DisconnectPacket{}

	// Some versions include a reason string
	if len(data) > 0 {
		reason, _, err := ReadString(data)
		if err == nil {
			dp.Reason = reason
		}
	}

	return dp, nil
}

// ParseDisconnectPacket parses a Disconnect packet from a Packet struct.
func ParseDisconnectPacket(p *Packet) (*DisconnectPacket, error) {
	if p.ID != PacketDisconnect {
		return nil, ErrInvalidPacketID
	}
	return ParseDisconnect(p.Data)
}
