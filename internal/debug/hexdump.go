package debug

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/klauspost/compress/zstd"
)

var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}
var zstdDecoder, _ = zstd.NewReader(nil)

// MaxHexDumpSize is the maximum number of bytes to include in hex dump output.
const MaxHexDumpSize = 4096

// LogChunk logs a data chunk with optional zstd decompression.
// No-op if debug mode is disabled.
func LogChunk(prefix string, num int, data []byte) {
	if !IsEnabled() {
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s #%d (%d bytes)\n", prefix, num, len(data)))

	// Try zstd decode if magic at start
	if zstdDecoder != nil && bytes.HasPrefix(data, zstdMagic) {
		if decoded, err := zstdDecoder.DecodeAll(data, nil); err == nil {
			sb.WriteString(fmt.Sprintf("── zstd: %d → %d bytes ──\n", len(data), len(decoded)))
			sb.WriteString(HexDump(decoded))
			log.Print(sb.String())
			return
		}
	}

	sb.WriteString(HexDump(data))
	log.Print(sb.String())
}

// HexDump formats bytes as hex + ASCII, limited to MaxHexDumpSize.
func HexDump(data []byte) string {
	if len(data) > MaxHexDumpSize {
		return hexDumpBytes(data[:MaxHexDumpSize]) +
			fmt.Sprintf("... (%d more bytes)\n", len(data)-MaxHexDumpSize)
	}
	return hexDumpBytes(data)
}

func hexDumpBytes(data []byte) string {
	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		sb.WriteString(fmt.Sprintf("%04x  ", i))
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				sb.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}
