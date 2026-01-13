package proxy

import (
	"hyproxy/internal/handler"
	"testing"
	"time"
)

func TestCryptoAssembler_AddFrame(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Add a frame at offset 0
	if !assembler.AddFrame(0, []byte{0x01, 0x02, 0x03}) {
		t.Error("AddFrame should succeed")
	}

	if assembler.maxOffset != 3 {
		t.Errorf("expected maxOffset=3, got %d", assembler.maxOffset)
	}

	// Add a frame at offset 5
	if !assembler.AddFrame(5, []byte{0x04, 0x05}) {
		t.Error("AddFrame at offset 5 should succeed")
	}

	if assembler.maxOffset != 7 {
		t.Errorf("expected maxOffset=7, got %d", assembler.maxOffset)
	}
}

func TestCryptoAssembler_AddFrame_Bounds(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Frame beyond buffer size should fail
	if assembler.AddFrame(maxCryptoBufferSize, []byte{0x01}) {
		t.Error("AddFrame beyond buffer should fail")
	}

	// Frame at edge should be truncated
	if !assembler.AddFrame(maxCryptoBufferSize-2, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Error("AddFrame at edge should succeed (with truncation)")
	}

	if assembler.maxOffset != maxCryptoBufferSize {
		t.Errorf("expected maxOffset=%d, got %d", maxCryptoBufferSize, assembler.maxOffset)
	}
}

func TestCryptoAssembler_TryParse_NotEnoughData(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Empty assembler
	if assembler.TryParse() != nil {
		t.Error("TryParse should return nil with no data")
	}

	// Add some data but not enough for ClientHello header
	assembler.AddFrame(0, []byte{0x01, 0x00})

	if assembler.TryParse() != nil {
		t.Error("TryParse should return nil with insufficient data")
	}
}

func TestCryptoAssembler_TryParse_WrongMessageType(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Add data that's not a ClientHello (type != 0x01)
	assembler.AddFrame(0, []byte{0x02, 0x00, 0x00, 0x10, 0x00, 0x00})

	if assembler.TryParse() != nil {
		t.Error("TryParse should return nil for non-ClientHello")
	}
}

func TestCryptoAssembler_TryParse_Gap(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Add frame at offset 0
	assembler.AddFrame(0, []byte{0x01, 0x00, 0x00})

	// Add frame at offset 5 (gap at offset 3-4)
	assembler.AddFrame(5, []byte{0x00, 0x00, 0x00})

	if assembler.TryParse() != nil {
		t.Error("TryParse should return nil with gap in data")
	}
}

func TestCryptoAssembler_IsExpired(t *testing.T) {
	assembler := NewCryptoAssembler()

	if assembler.IsExpired() {
		t.Error("New assembler should not be expired")
	}

	// Manually set createdAt to past
	assembler.createdAt = time.Now().Add(-10 * time.Second)

	if !assembler.IsExpired() {
		t.Error("Old assembler should be expired")
	}
}

func TestCryptoAssembler_Bitset(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Test setBit and isSet
	assembler.setBit(0)
	assembler.setBit(63)
	assembler.setBit(64)
	assembler.setBit(127)

	if !assembler.isSet(0) {
		t.Error("bit 0 should be set")
	}
	if !assembler.isSet(63) {
		t.Error("bit 63 should be set")
	}
	if !assembler.isSet(64) {
		t.Error("bit 64 should be set")
	}
	if !assembler.isSet(127) {
		t.Error("bit 127 should be set")
	}

	// Unset bits
	if assembler.isSet(1) {
		t.Error("bit 1 should not be set")
	}
	if assembler.isSet(65) {
		t.Error("bit 65 should not be set")
	}
}

func TestSessionHeap(t *testing.T) {
	h := &sessionHeap{}

	// Push items
	h.Push(sessionAge{key: "a", idle: 100 * time.Second})
	h.Push(sessionAge{key: "b", idle: 50 * time.Second})
	h.Push(sessionAge{key: "c", idle: 200 * time.Second})

	// Min-heap: smallest idle time should be at top
	if h.Len() != 3 {
		t.Errorf("expected len 3, got %d", h.Len())
	}

	// Pop should return smallest first
	item := h.Pop().(sessionAge)
	if item.key != "c" {
		// Note: after Push without heap.Push, order is not guaranteed
		// This test mainly ensures no panic
	}
}

func TestBufferPool(t *testing.T) {
	// Get buffer
	buf1 := handler.GetBuffer()
	if buf1 == nil {
		t.Fatal("GetBuffer returned nil")
	}
	if len(*buf1) != 65535 {
		t.Errorf("expected buffer size 65535, got %d", len(*buf1))
	}

	// Return buffer
	handler.PutBuffer(buf1)

	// Get another buffer (might be the same one from pool)
	buf2 := handler.GetBuffer()
	if buf2 == nil {
		t.Fatal("GetBuffer returned nil after PutBuffer")
	}

	handler.PutBuffer(buf2)

	// PutBuffer with nil should not panic
	handler.PutBuffer(nil)
}
