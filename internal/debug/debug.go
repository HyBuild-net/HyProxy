package debug

import (
	"log"
	"sync/atomic"
)

var enabled atomic.Bool

// Enable turns on debug logging.
func Enable() {
	enabled.Store(true)
}

// Disable turns off debug logging.
func Disable() {
	enabled.Store(false)
}

// IsEnabled returns whether debug logging is enabled.
func IsEnabled() bool {
	return enabled.Load()
}

// Printf logs a debug message if debug mode is enabled.
func Printf(format string, v ...any) {
	if enabled.Load() {
		log.Printf("[DEBUG] "+format, v...)
	}
}
