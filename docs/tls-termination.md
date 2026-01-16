# TLS Termination

The `terminator` handler terminates QUIC TLS and bridges to backend servers. This allows inspection of raw `hytale/1` protocol traffic.

## Requirements

Requires the [HytaleCustomCert](https://hybuildnet.github.io/HytaleCustomCert/) plugin on backend servers with `bypassClientCertificateBinding: true`. This allows the proxy to use the same certificate as the backend server.

## Basic usage

```json
{
  "listen": ":5520",
  "handlers": [
    {
      "type": "sni-router",
      "config": {
        "routes": {
          "play.example.com": "10.0.0.1:5521"
        }
      }
    },
    {
      "type": "terminator",
      "config": {
        "listen": "auto",
        "certs": {
          "default": {
            "cert": "/etc/quic-relay/server.crt",
            "key": "/etc/quic-relay/server.key"
          }
        }
      }
    },
    {
      "type": "forwarder"
    }
  ]
}
```

## Per-target certificates

Different backends can use different certificates:

```json
{
  "type": "terminator",
  "config": {
    "listen": "auto",
    "certs": {
      "default": {
        "cert": "/etc/quic-relay/server.crt",
        "key": "/etc/quic-relay/server.key"
      },
      "targets": {
        "10.0.0.2:5522": {
          "cert": "/etc/quic-relay/dev.crt",
          "key": "/etc/quic-relay/dev.key"
        }
      }
    }
  }
}
```

## Config options

| Field | Description |
|-------|-------------|
| `listen` | Internal listener address (`auto` for ephemeral port) |
| `certs.default` | Fallback certificate |
| `certs.targets` | Backend address to certificate mapping |

### Certificate config

| Field | Description |
|-------|-------------|
| `cert` | Path to TLS certificate |
| `key` | Path to TLS private key |
| `backend_mtls` | Use certificate for backend mTLS (default: `true`) |

### Packet logging

For debugging protocol traffic:

| Field | Description |
|-------|-------------|
| `log_client_packets` | Number of client packets to log (0 = disabled) |
| `log_server_packets` | Number of server packets to log (0 = disabled) |
| `skip_client_packets` | Skip first N packets before logging |
| `skip_server_packets` | Skip first N packets before logging |
| `max_packet_size` | Skip packets larger than this (default: 1MB) |

## Standalone library

The terminator is available as a standalone Go library: [hytale-terminating-proxy](https://github.com/HyBuildNet/hytale-terminating-proxy)
