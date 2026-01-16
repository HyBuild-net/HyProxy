package protohytale

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	ErrPacketTooLarge = errors.New("packet exceeds maximum size")
	ErrInvalidHeader  = errors.New("invalid packet header")
)

const (
	HeaderSize     = 8                // 4 bytes length + 4 bytes packet ID
	MaxPacketSize  = 16 * 1024 * 1024 // 16MB reasonable max
	DefaultBufSize = 64 * 1024        // 64KB initial buffer
)

// PacketReader reads framed Hytale packets from a QUIC stream.
// It handles partial reads across multiple Read() calls.
type PacketReader struct {
	r        io.Reader
	buf      []byte // Reusable buffer
	buffered int    // Bytes currently in buffer
	offset   int    // Read offset into buffer
}

// NewPacketReader creates a reader that frames packets from a stream.
func NewPacketReader(r io.Reader) *PacketReader {
	return &PacketReader{
		r:   r,
		buf: make([]byte, DefaultBufSize),
	}
}

// NewPacketReaderSize creates a reader with custom initial buffer size.
func NewPacketReaderSize(r io.Reader, size int) *PacketReader {
	if size < HeaderSize {
		size = DefaultBufSize
	}
	return &PacketReader{
		r:   r,
		buf: make([]byte, size),
	}
}

// ReadPacket reads and returns the next complete packet.
// Returns (packet, nil) on success, (nil, io.EOF) at stream end,
// or (nil, error) on failure.
func (pr *PacketReader) ReadPacket() (*Packet, error) {
	// Ensure we have at least the header
	if err := pr.ensureBytes(HeaderSize); err != nil {
		return nil, err
	}

	// Parse header (little-endian)
	length := binary.LittleEndian.Uint32(pr.buf[pr.offset:])
	packetID := binary.LittleEndian.Uint32(pr.buf[pr.offset+4:])

	// Sanity check
	if length > MaxPacketSize {
		return nil, ErrPacketTooLarge
	}

	totalSize := HeaderSize + int(length)

	// Ensure we have the complete packet
	if err := pr.ensureBytes(totalSize); err != nil {
		return nil, err
	}

	// Extract packet data (copy to avoid buffer reuse issues)
	data := make([]byte, length)
	copy(data, pr.buf[pr.offset+HeaderSize:pr.offset+totalSize])

	// Advance offset
	pr.offset += totalSize

	return &Packet{
		ID:   packetID,
		Data: data,
	}, nil
}

// ReadPacketNoCopy reads the next packet without copying data.
// The returned data slice is only valid until the next Read call.
// Use this for high-throughput scenarios where you process immediately.
func (pr *PacketReader) ReadPacketNoCopy() (id uint32, data []byte, err error) {
	if err := pr.ensureBytes(HeaderSize); err != nil {
		return 0, nil, err
	}

	length := binary.LittleEndian.Uint32(pr.buf[pr.offset:])
	id = binary.LittleEndian.Uint32(pr.buf[pr.offset+4:])

	if length > MaxPacketSize {
		return 0, nil, ErrPacketTooLarge
	}

	totalSize := HeaderSize + int(length)

	if err := pr.ensureBytes(totalSize); err != nil {
		return 0, nil, err
	}

	data = pr.buf[pr.offset+HeaderSize : pr.offset+totalSize]
	pr.offset += totalSize

	return id, data, nil
}

// ensureBytes ensures at least n bytes are available from offset.
// Compacts the buffer and reads more data as needed.
func (pr *PacketReader) ensureBytes(n int) error {
	available := pr.buffered - pr.offset

	if available >= n {
		return nil
	}

	// Compact: move unread data to start
	if pr.offset > 0 {
		copy(pr.buf, pr.buf[pr.offset:pr.buffered])
		pr.buffered = available
		pr.offset = 0
	}

	// Grow buffer if needed
	if n > len(pr.buf) {
		newSize := len(pr.buf) * 2
		if newSize < n {
			newSize = n
		}
		newBuf := make([]byte, newSize)
		copy(newBuf, pr.buf[:pr.buffered])
		pr.buf = newBuf
	}

	// Read until we have enough
	for pr.buffered < n {
		nr, err := pr.r.Read(pr.buf[pr.buffered:])
		pr.buffered += nr
		if err != nil {
			if err == io.EOF && pr.buffered > 0 && pr.buffered < n {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}

	return nil
}

// Reset resets the reader to use a new underlying reader.
// Allows reusing the buffer allocation for a new stream.
func (pr *PacketReader) Reset(r io.Reader) {
	pr.r = r
	pr.buffered = 0
	pr.offset = 0
}

// Buffered returns the number of bytes buffered but not yet consumed.
func (pr *PacketReader) Buffered() int {
	return pr.buffered - pr.offset
}

// PacketWriter writes framed Hytale packets to a stream.
type PacketWriter struct {
	w   io.Writer
	buf [HeaderSize]byte
}

// NewPacketWriter creates a writer that frames packets for a stream.
func NewPacketWriter(w io.Writer) *PacketWriter {
	return &PacketWriter{w: w}
}

// WritePacket writes a complete packet to the stream.
func (pw *PacketWriter) WritePacket(p *Packet) error {
	return pw.Write(p.ID, p.Data)
}

// Write writes a packet with the given ID and data.
func (pw *PacketWriter) Write(id uint32, data []byte) error {
	binary.LittleEndian.PutUint32(pw.buf[0:4], uint32(len(data)))
	binary.LittleEndian.PutUint32(pw.buf[4:8], id)

	if _, err := pw.w.Write(pw.buf[:]); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := pw.w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// Reset resets the writer to use a new underlying writer.
func (pw *PacketWriter) Reset(w io.Writer) {
	pw.w = w
}
