package handler

import (
	"encoding/json"
	"fmt"
)

// HandlerConfig represents a handler configuration from JSON.
type HandlerConfig struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config,omitempty"`
}

// HandlerFactory creates a handler from JSON config.
type HandlerFactory func(config json.RawMessage) (Handler, error)

// registry holds all registered handler factories.
var registry = map[string]HandlerFactory{}

// Register adds a handler factory to the registry.
func Register(name string, factory HandlerFactory) {
	registry[name] = factory
}

// BuildChain creates a handler chain from configuration.
func BuildChain(configs []HandlerConfig) (*Chain, error) {
	var handlers []Handler
	for _, cfg := range configs {
		factory, ok := registry[cfg.Type]
		if !ok {
			return nil, fmt.Errorf("unknown handler type: %s", cfg.Type)
		}
		h, err := factory(cfg.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create handler %s: %w", cfg.Type, err)
		}
		handlers = append(handlers, h)
	}
	return NewChain(handlers...), nil
}

// ListHandlers returns all registered handler names.
func ListHandlers() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
