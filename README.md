# HyProxy

A reverse proxy for Hytale servers. Route players to different backends based on the domain they connect to, enabling multiple servers behind a single IP address.

## Build

```bash
make build
```

Produces `bin/proxy`.

## Usage

```bash
# With config file
./bin/proxy -config config.json

# With inline JSON
./bin/proxy -config '{"listen":":5520","handlers":[{"type":"simple-router","config":{"backend":"10.0.0.1:5520"}},{"type":"forwarder"}]}'
```

### Signals

| Signal | Effect |
|--------|--------|
| `SIGHUP` | Reload config (only when using a file) |
| `SIGINT` | Shutdown |

### Environment Variables

Environment variables are used as fallback when the config does not specify a value.

| Variable | Description | Default |
|----------|-------------|---------|
| `HYPROXY_LISTEN` | Listen address | `:5520` |

## Configuration

```json
{
  "listen": ":5520",
  "handlers": [
    {"type": "handler-name", "config": {}}
  ]
}
```

## Handlers

Handlers form a chain. Each handler processes the connection and either passes it to the next handler (`Continue`), handles it (`Handled`), or drops it (`Drop`).

### sni-router

Routes connections based on SNI.

```json
{
  "type": "sni-router",
  "config": {
    "routes": {
      "play.example.com": "myserver.internal.dev:5520",
      "lobby.example.com": ["[2001:db8::1]:5520", "127.0.0.1:5520"]
    }
  }
}
```

Each route can be a single backend (string) or multiple backends (array) for round-robin load balancing. Connections with unknown SNI are dropped.

### simple-router

Routes all connections to one or more backends.

Single backend:
```json
{
  "type": "simple-router",
  "config": {
    "backend": "10.0.0.1:5520"
  }
}
```

Multiple backends (round-robin):
```json
{
  "type": "simple-router",
  "config": {
    "backends": ["127.0.0.1:5520", "[2001:db8::1]:5520"]
  }
}
```

### forwarder

Forwards packets to the backend. Must be the last handler in the chain. Reads the `backend` address from context (set by a router handler).

```json
{
  "type": "forwarder"
}
```

### logsni

Logs the SNI of each connection. Passes through.

```json
{
  "type": "logsni"
}
```

## Examples

### Simple Proxy

Forward all traffic to a single backend:

```json
{
  "listen": ":5520",
  "handlers": [
    {"type": "simple-router", "config": {"backend": "10.0.0.1:5520"}},
    {"type": "forwarder"}
  ]
}
```

### Load Balancing

Distribute traffic across multiple backends:

```json
{
  "listen": ":5520",
  "handlers": [
    {
      "type": "simple-router",
      "config": {
        "backends": ["10.0.0.1:5520", "10.0.0.2:5525", "[2001:db8::1]:5520"]
      }
    },
    {"type": "forwarder"}
  ]
}
```

### SNI Routing

Route to different backends based on hostname:

```json
{
  "listen": ":5520",
  "handlers": [
    {"type": "logsni"},
    {
      "type": "sni-router",
      "config": {
        "routes": {
          "play.example.com": "10.0.0.1:5520",
          "lobby.example.com": ["10.0.0.2:5520", "[2001:db8::1]:5520"],
          "minigames.example.com": "myserver.internal.dev:56777"
        }
      }
    },
    {"type": "forwarder"}
  ]
}
```

## License

MIT License. See [LICENSE](LICENSE) for details.
