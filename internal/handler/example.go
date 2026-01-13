package handler

import "encoding/json"

func init() {
	Register("example", NewExampleHandler)
}

// ExampleHandler is a no-op handler for demonstration and testing.
type ExampleHandler struct{}

// NewExampleHandler creates a new example handler.
func NewExampleHandler(_ json.RawMessage) (Handler, error) {
	return &ExampleHandler{}, nil
}

// Name returns the handler name.
func (h *ExampleHandler) Name() string { return "example" }

// OnConnect does nothing.
func (h *ExampleHandler) OnConnect(ctx *Context) Result { return Result{Action: Continue} }

// OnPacket does nothing.
func (h *ExampleHandler) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	return Result{Action: Continue}
}

// OnDisconnect does nothing.
func (h *ExampleHandler) OnDisconnect(ctx *Context) {}
