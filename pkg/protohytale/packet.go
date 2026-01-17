package protohytale

import (
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Packet IDs
const (
	PacketConnect    uint32 = 0x00000000
	PacketDisconnect uint32 = 0x00000001
)

// Packet represents a decoded Hytale protocol packet.
type Packet struct {
	ID   uint32 // Packet type identifier
	Data []byte // Payload (may be Zstd compressed)
}

// zstdMagic bytes for detecting compressed packets.
var zstdMagic = [4]byte{0x28, 0xB5, 0x2F, 0xFD}

// IsCompressed returns true if the packet data is Zstd compressed.
func (p *Packet) IsCompressed() bool {
	return len(p.Data) >= 4 &&
		p.Data[0] == zstdMagic[0] &&
		p.Data[1] == zstdMagic[1] &&
		p.Data[2] == zstdMagic[2] &&
		p.Data[3] == zstdMagic[3]
}

// Decompress returns decompressed data if compressed, or original data.
// Uses a shared decoder for efficiency.
func (p *Packet) Decompress() ([]byte, error) {
	if !p.IsCompressed() {
		return p.Data, nil
	}
	return getDecoder().DecodeAll(p.Data, nil)
}

// DecompressTo decompresses into the provided buffer (reused if possible).
// Returns the decompressed data which may be a different slice.
func (p *Packet) DecompressTo(dst []byte) ([]byte, error) {
	if !p.IsCompressed() {
		return p.Data, nil
	}
	return getDecoder().DecodeAll(p.Data, dst[:0])
}

// sharedDecoder is lazily initialized Zstd decoder.
var (
	sharedDecoder     *zstd.Decoder
	sharedDecoderOnce sync.Once
)

func getDecoder() *zstd.Decoder {
	sharedDecoderOnce.Do(func() {
		var err error
		sharedDecoder, err = zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(64*1024*1024), // 64MB max
		)
		if err != nil {
			panic("failed to create zstd decoder: " + err.Error())
		}
	})
	return sharedDecoder
}

// PacketName returns a human-readable name for known packet IDs.
func PacketName(id uint32) string {
	switch id {
	case PacketConnect:
		return "Connect"
	case PacketDisconnect:
		return "Disconnect"
	default:
		return ""
	}
}
