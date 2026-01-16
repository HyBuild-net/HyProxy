package protohytale

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

var (
	ErrVarIntTooLong = errors.New("varint exceeds 5 bytes")
	ErrStringTooLong = errors.New("string exceeds max length")
	ErrInvalidUTF8   = errors.New("invalid utf-8 string")
)

const MaxStringLength = 256

// ReadVarInt reads a Hytale VarInt (7-bit encoding, max 5 bytes, unsigned only).
// Returns (value, bytesRead, error).
func ReadVarInt(data []byte) (uint32, int, error) {
	var result uint32
	var shift uint

	for i := 0; i < 5; i++ {
		if i >= len(data) {
			return 0, 0, io.ErrUnexpectedEOF
		}

		b := data[i]
		result |= uint32(b&0x7F) << shift

		if b&0x80 == 0 {
			return result, i + 1, nil
		}

		shift += 7
	}

	return 0, 0, ErrVarIntTooLong
}

// WriteVarInt encodes a uint32 as a Hytale VarInt.
// Returns the encoded bytes.
func WriteVarInt(value uint32) []byte {
	var buf [5]byte
	n := 0

	for {
		b := byte(value & 0x7F)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		buf[n] = b
		n++
		if value == 0 {
			break
		}
	}

	return buf[:n]
}

// VarIntSize returns the number of bytes needed to encode a value as VarInt.
func VarIntSize(value uint32) int {
	switch {
	case value < 1<<7:
		return 1
	case value < 1<<14:
		return 2
	case value < 1<<21:
		return 3
	case value < 1<<28:
		return 4
	default:
		return 5
	}
}

// ReadString reads a VarInt-prefixed UTF-8 string.
// Returns (string, bytesRead, error).
func ReadString(data []byte) (string, int, error) {
	length, n, err := ReadVarInt(data)
	if err != nil {
		return "", 0, err
	}

	if length > MaxStringLength {
		return "", 0, ErrStringTooLong
	}

	end := n + int(length)
	if end > len(data) {
		return "", 0, io.ErrUnexpectedEOF
	}

	return string(data[n:end]), end, nil
}

// WriteString encodes a string with VarInt length prefix.
func WriteString(s string) []byte {
	lenBytes := WriteVarInt(uint32(len(s)))
	result := make([]byte, len(lenBytes)+len(s))
	copy(result, lenBytes)
	copy(result[len(lenBytes):], s)
	return result
}

// ReadUUID reads a 16-byte big-endian UUID.
func ReadUUID(data []byte) ([16]byte, int, error) {
	var uuid [16]byte
	if len(data) < 16 {
		return uuid, 0, io.ErrUnexpectedEOF
	}
	copy(uuid[:], data[:16])
	return uuid, 16, nil
}

// ReadUint8 reads a single byte.
func ReadUint8(data []byte) (uint8, int, error) {
	if len(data) < 1 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return data[0], 1, nil
}

// ReadUint16LE reads a little-endian uint16.
func ReadUint16LE(data []byte) (uint16, int, error) {
	if len(data) < 2 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return binary.LittleEndian.Uint16(data), 2, nil
}

// ReadUint32LE reads a little-endian uint32.
func ReadUint32LE(data []byte) (uint32, int, error) {
	if len(data) < 4 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return binary.LittleEndian.Uint32(data), 4, nil
}

// ReadUint64LE reads a little-endian uint64.
func ReadUint64LE(data []byte) (uint64, int, error) {
	if len(data) < 8 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return binary.LittleEndian.Uint64(data), 8, nil
}

// ReadInt32LE reads a little-endian int32.
func ReadInt32LE(data []byte) (int32, int, error) {
	if len(data) < 4 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return int32(binary.LittleEndian.Uint32(data)), 4, nil
}

// ReadFloat32LE reads a little-endian float32.
func ReadFloat32LE(data []byte) (float32, int, error) {
	if len(data) < 4 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	bits := binary.LittleEndian.Uint32(data)
	return math.Float32frombits(bits), 4, nil
}

// ReadFloat16 reads a half-precision (16-bit) float as float32.
func ReadFloat16(data []byte) (float32, int, error) {
	if len(data) < 2 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	bits := binary.LittleEndian.Uint16(data)
	return float16ToFloat32(bits), 2, nil
}

// ReadBytes reads n bytes from data.
func ReadBytes(data []byte, n int) ([]byte, int, error) {
	if len(data) < n {
		return nil, 0, io.ErrUnexpectedEOF
	}
	result := make([]byte, n)
	copy(result, data[:n])
	return result, n, nil
}

// ReadHostAddress reads a hostname string and port.
func ReadHostAddress(data []byte) (host string, port uint16, bytesRead int, err error) {
	host, n, err := ReadString(data)
	if err != nil {
		return "", 0, 0, err
	}

	if len(data) < n+2 {
		return "", 0, 0, io.ErrUnexpectedEOF
	}

	port = binary.LittleEndian.Uint16(data[n:])
	return host, port, n + 2, nil
}

// float16ToFloat32 converts a half-precision float to float32.
func float16ToFloat32(h uint16) float32 {
	sign := uint32(h>>15) & 1
	exp := uint32(h>>10) & 0x1F
	mant := uint32(h) & 0x3FF

	var f uint32
	switch exp {
	case 0:
		if mant == 0 {
			// Zero
			f = sign << 31
		} else {
			// Subnormal
			exp = 127 - 14
			for mant&0x400 == 0 {
				mant <<= 1
				exp--
			}
			mant &= 0x3FF
			f = (sign << 31) | (exp << 23) | (mant << 13)
		}
	case 31:
		// Inf or NaN
		f = (sign << 31) | (0xFF << 23) | (mant << 13)
	default:
		// Normal
		f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13)
	}

	return math.Float32frombits(f)
}
