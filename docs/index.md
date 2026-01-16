---
layout: doc
title: QUIC Relay - Reverse Proxy for Hytale
description: Route multiple Hytale servers through a single IP using SNI-based routing and TLS termination. Open source QUIC reverse proxy with load balancing.
head:
  - - meta
    - name: keywords
      content: hytale, hytale server, hytale proxy, hytale reverse proxy, hytale multiple servers, quic, quic proxy, sni routing, udp proxy, load balancer
  - - meta
    - property: og:title
      content: QUIC Relay - Reverse Proxy for Hytale
  - - meta
    - property: og:description
      content: Route multiple Hytale servers through a single IP using SNI-based routing and TLS termination.
  - - meta
    - property: og:type
      content: website
---

# QUIC Relay

A QUIC reverse proxy with SNI-based routing and optional TLS termination for protocol inspection and manipulation. Built for Hytale servers, works with any QUIC-based protocol.

## What it does

Routes connections to backends based on domain (SNI). Optionally terminates TLS for protocol inspection and manipulation. Multiple servers can share a single IP and port.

```
┌──────────────┐                        ┌─────────────────────┐
│   Client A   │──play.example.com────▶│                     │──▶ Backend 1
├──────────────┤                        │     QUIC Relay      │
│   Client B   │──lobby.example.com───▶│     (port 5520)     │──▶ Backend 2
├──────────────┤                        │                     │
│   Client C   │──other.example.com───▶│                     │──▶ Backend 3
└──────────────┘                        └─────────────────────┘
```

## Why this exists

Hytale uses QUIC on UDP port 5520. Unlike TCP-based games, there's no established method (like SRV records for Minecraft) to redirect players to different ports. Running multiple servers on one IP currently requires either:

- Different ports per server (inconvenient for players)
- A reverse proxy that routes based on SNI (this project)

## Architecture

The proxy uses a handler chain. Each handler processes connections sequentially and decides whether to:

- **Continue** — pass to the next handler
- **Handled** — stop processing, connection was handled
- **Drop** — terminate the connection

This design allows combining handlers for different purposes: logging, rate limiting, routing, and forwarding.
