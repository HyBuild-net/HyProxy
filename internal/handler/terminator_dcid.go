package handler

import (
	"encoding/hex"
	"net"
	"sync"
	"time"
)

// dcidEntry holds a DCID with its creation timestamp.
type dcidEntry struct {
	dcid    string
	created time.Time
}

// dcidTracker wraps a PacketConn to track QUIC DCID → remote address mappings.
// Used to correlate connections between OnConnect and the internal listener.
type dcidTracker struct {
	net.PacketConn
	mu     sync.RWMutex
	byAddr map[string]dcidEntry // remote_addr → dcid entry

	ctx    chan struct{}
	closed bool
}

func newDCIDTracker(conn net.PacketConn) *dcidTracker {
	t := &dcidTracker{
		PacketConn: conn,
		byAddr:     make(map[string]dcidEntry),
		ctx:        make(chan struct{}),
	}
	go t.cleanupLoop()
	return t
}

// ReadFrom intercepts packets to extract and store DCIDs.
// Only stores the FIRST DCID per address to handle QUIC CID changes during handshake.
func (t *dcidTracker) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = t.PacketConn.ReadFrom(p)
	if err == nil && n > 6 {
		if dcid := parseQUICDCID(p[:n]); dcid != "" {
			t.mu.Lock()
			// Only store first DCID per address (don't overwrite)
			// This is important because QUIC may change DCIDs during handshake
			if _, exists := t.byAddr[addr.String()]; !exists {
				t.byAddr[addr.String()] = dcidEntry{
					dcid:    dcid,
					created: time.Now(),
				}
			}
			t.mu.Unlock()
		}
	}
	return
}

// GetDCID returns the DCID associated with a remote address.
func (t *dcidTracker) GetDCID(addr string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if entry, ok := t.byAddr[addr]; ok {
		return entry.dcid
	}
	return ""
}

// Delete removes the mapping for a remote address.
func (t *dcidTracker) Delete(addr string) {
	t.mu.Lock()
	delete(t.byAddr, addr)
	t.mu.Unlock()
}

// Close stops the cleanup goroutine and closes the underlying connection.
func (t *dcidTracker) Close() error {
	t.mu.Lock()
	if !t.closed {
		t.closed = true
		close(t.ctx)
	}
	t.mu.Unlock()
	return t.PacketConn.Close()
}

// cleanupLoop periodically removes stale entries (connections that never completed).
// Entries older than 60 seconds are removed - this is more than enough for QUIC handshake.
func (t *dcidTracker) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	const maxAge = 60 * time.Second

	for {
		select {
		case <-ticker.C:
			t.mu.Lock()
			now := time.Now()
			for addr, entry := range t.byAddr {
				if now.Sub(entry.created) > maxAge {
					delete(t.byAddr, addr)
				}
			}
			t.mu.Unlock()
		case <-t.ctx:
			return
		}
	}
}

// parseQUICDCID extracts the Destination Connection ID from a QUIC packet.
// Returns hex-encoded DCID or empty string if not a valid QUIC long header packet.
//
// QUIC Long Header format (RFC 9000):
//
//	Header Form (1) = 1
//	Fixed Bit (1) = 1
//	Long Packet Type (2)
//	Type-Specific Bits (4)
//	Version (32)
//	DCID Length (8)
//	DCID (0-255 bytes)
//	SCID Length (8)
//	SCID (0-255 bytes)
//	...
func parseQUICDCID(packet []byte) string {
	if len(packet) < 6 {
		return ""
	}

	// Long header: first bit must be 1
	if packet[0]&0x80 == 0 {
		return "" // Short header, no DCID available in predictable position
	}

	// Skip: header byte (1) + version (4) = 5 bytes
	// DCID length is at offset 5
	dcidLen := int(packet[5])
	if dcidLen == 0 || len(packet) < 6+dcidLen {
		return ""
	}

	return hex.EncodeToString(packet[6 : 6+dcidLen])
}
