package handler

import "sync"

// packetPool provides reusable byte buffers for UDP packets.
// Using sync.Pool eliminates per-packet allocations in hot paths.
var packetPool = sync.Pool{
	New: func() any {
		// Max UDP packet size
		buf := make([]byte, 65535)
		return &buf
	},
}

// GetBuffer returns a buffer from the pool.
// Caller must return it via PutBuffer after use.
func GetBuffer() *[]byte {
	return packetPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool.
// Buffer contents are NOT cleared for performance.
func PutBuffer(buf *[]byte) {
	if buf != nil {
		packetPool.Put(buf)
	}
}
