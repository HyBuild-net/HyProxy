---
layout: doc
title: QUIC Relay - SNI-based Reverse Proxy for Hytale and QUIC
description: Route multiple Hytale servers through a single IP and port using SNI-based routing. Open source QUIC reverse proxy with load balancing and rate limiting.
head:
  - - meta
    - name: keywords
      content: hytale, hytale server, hytale proxy, hytale reverse proxy, hytale multiple servers, quic, quic proxy, sni routing, udp proxy, load balancer
  - - meta
    - property: og:title
      content: QUIC Relay - SNI-based Reverse Proxy
  - - meta
    - property: og:description
      content: Route multiple Hytale servers through a single IP and port using SNI-based routing.
  - - meta
    - property: og:type
      content: website
---

# QUIC Relay

A reverse proxy for routing QUIC connections based on SNI (Server Name Indication). Built for Hytale servers, works with any QUIC-based protocol.

## What it does

The proxy inspects the SNI field in incoming QUIC handshakes and routes connections to different backends based on the hostname. This allows multiple servers to share a single public IP and port.

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
