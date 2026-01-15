package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"quic-relay/internal/debug"
)

func init() {
	Register("terminator", NewTerminatorHandler)
}

// TerminatorConfig holds configuration for the terminator handler.
type TerminatorConfig struct {
	Listen      string `json:"listen"`       // ":5521" or "auto" for ephemeral port
	Cert        string `json:"cert"`         // Path to TLS certificate
	Key         string `json:"key"`          // Path to TLS private key
	BackendMTLS bool   `json:"backend_mtls"` // Use same cert as client cert for backend mTLS

	// Packet logging settings (per direction)
	LogClientPackets  int `json:"log_client_packets"`  // Number of client packets to log (0 = disabled)
	LogServerPackets  int `json:"log_server_packets"`  // Number of server packets to log (0 = disabled)
	SkipClientPackets int `json:"skip_client_packets"` // Client packets to skip before logging
	SkipServerPackets int `json:"skip_server_packets"` // Server packets to skip before logging
	MaxPacketSize     int `json:"max_packet_size"`     // Skip packets larger than this (0 = no limit, default 1MB)
}

// TerminatorHandler terminates QUIC connections and bridges them to backends.
// It runs an internal QUIC listener and uses the transparent proxy as a frontend.
type TerminatorHandler struct {
	config       TerminatorConfig
	transport    *quic.Transport
	listener     *quic.Listener
	tracker      *dcidTracker
	internalAddr string
	clientCert   *tls.Certificate // Client certificate for backend mTLS

	// DCID → backend mapping (set by OnConnect, read by handleConnection)
	backends sync.Map // dcid (hex string) → backend address (string)

	// Session tracking
	sessionCount atomic.Int64
	sessions     sync.Map // sessionID → *terminatorSession

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewTerminatorHandler creates a new terminator handler.
func NewTerminatorHandler(raw json.RawMessage) (Handler, error) {
	var cfg TerminatorConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}

	h := &TerminatorHandler{config: cfg}
	h.ctx, h.cancel = context.WithCancel(context.Background())

	// Load certificate
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, err
	}

	// Store certificate for backend mTLS if enabled
	if cfg.BackendMTLS {
		h.clientCert = &cert
		log.Printf("[terminator] backend mTLS enabled")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Accept any ALPN protocol the client offers
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   chi.SupportedProtos, // Mirror client's offered protocols
			}, nil
		},
	}

	// Setup internal listener address
	addr := cfg.Listen
	if addr == "auto" || addr == "" {
		addr = "localhost:0" // Ephemeral port
	}

	// Create UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	// Wrap with DCID tracker
	h.tracker = newDCIDTracker(udpConn)

	// Create QUIC transport with our tracked connection
	h.transport = &quic.Transport{Conn: h.tracker}

	// Start QUIC listener on transport
	listener, err := h.transport.Listen(tlsConfig, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		h.tracker.Close()
		return nil, err
	}

	h.listener = listener
	h.internalAddr = udpConn.LocalAddr().String()

	log.Printf("[terminator] internal listener on %s", h.internalAddr)

	// Start accept loop in goroutine
	h.wg.Add(1)
	go h.acceptLoop()

	return h, nil
}

// Name returns the handler name.
func (h *TerminatorHandler) Name() string {
	return "terminator"
}

// OnConnect stores backend mapping by DCID and redirects to internal listener.
func (h *TerminatorHandler) OnConnect(ctx *Context) Result {
	backend := ctx.GetString("backend")
	if backend == "" {
		return Result{Action: Drop, Error: errors.New("no backend")}
	}

	// Extract DCID from InitialPacket
	dcid := parseQUICDCID(ctx.InitialPacket)
	if dcid == "" {
		return Result{Action: Drop, Error: errors.New("no DCID in packet")}
	}

	// Store backend by DCID (not SNI!)
	h.backends.Store(dcid, backend)

	sni := ""
	if ctx.Hello != nil {
		sni = ctx.Hello.SNI
	}
	dcidShort := dcid
	if len(dcid) > 8 {
		dcidShort = dcid[:8]
	}
	log.Printf("[terminator] %s (dcid=%s) → %s (via %s)", sni, dcidShort, backend, h.internalAddr)

	// Redirect to internal listener
	ctx.Set("backend", h.internalAddr)
	return Result{Action: Continue}
}

// OnPacket does nothing - ForwarderHandler handles packet forwarding.
func (h *TerminatorHandler) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	return Result{Action: Continue}
}

// OnDisconnect cleans up backend mapping if connection didn't reach handleConnection.
func (h *TerminatorHandler) OnDisconnect(ctx *Context) {
	// Clean up in case connection was dropped before handleConnection ran
	if ctx.InitialPacket != nil {
		dcid := parseQUICDCID(ctx.InitialPacket)
		if dcid != "" {
			h.backends.Delete(dcid)
		}
	}
}

// acceptLoop accepts connections on the internal listener.
func (h *TerminatorHandler) acceptLoop() {
	defer h.wg.Done()

	log.Printf("[terminator] accept loop started")

	for {
		debug.Printf("[terminator] calling Accept()...")
		conn, err := h.listener.Accept(h.ctx)
		if err != nil {
			log.Printf("[terminator] accept loop ended: %v", err)
			return
		}

		debug.Printf("[terminator] accepted connection from %s", conn.RemoteAddr())
		h.wg.Add(1)
		go h.handleConnection(conn)
	}
}

// handleConnection handles a single client connection.
func (h *TerminatorHandler) handleConnection(clientConn *quic.Conn) {
	defer h.wg.Done()

	// Get DCID from tracker using remote address
	remoteAddr := clientConn.RemoteAddr().String()
	dcid := h.tracker.GetDCID(remoteAddr)
	if dcid == "" {
		log.Printf("[terminator] no DCID mapping for %s", remoteAddr)
		clientConn.CloseWithError(0x01, "no dcid mapping")
		return
	}

	// Lookup backend by DCID
	entry, ok := h.backends.Load(dcid)
	if !ok {
		dcidShort := dcid
		if len(dcid) > 8 {
			dcidShort = dcid[:8]
		}
		log.Printf("[terminator] no backend for DCID %s", dcidShort)
		clientConn.CloseWithError(0x01, "no backend")
		h.tracker.Delete(remoteAddr)
		return
	}
	backend := entry.(string)

	// Cleanup mappings (one-time use)
	h.tracker.Delete(remoteAddr)
	h.backends.Delete(dcid)

	// Get SNI and ALPN from TLS state for backend connection
	tlsState := clientConn.ConnectionState().TLS
	sni := tlsState.ServerName
	alpn := tlsState.NegotiatedProtocol

	// Dial backend with timeout
	dialCtx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
	defer cancel()

	backendTLS := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni, // Pass through SNI
	}
	if alpn != "" {
		backendTLS.NextProtos = []string{alpn}
	}
	// Add client certificate for mTLS if configured
	if h.clientCert != nil {
		backendTLS.Certificates = []tls.Certificate{*h.clientCert}
	}

	serverConn, err := quic.DialAddr(dialCtx, backend, backendTLS, &quic.Config{
		MaxIdleTimeout:       30 * time.Second,
		HandshakeIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		log.Printf("[terminator] dial backend %s failed: %v", backend, err)
		clientConn.CloseWithError(0x02, "backend unreachable")
		return
	}

	// Check if client is still connected
	select {
	case <-clientConn.Context().Done():
		serverConn.CloseWithError(0, "client gone")
		return
	default:
	}

	// Create session and start bridging
	session := newTerminatorSession(clientConn, serverConn, &h.config)
	sessionID := h.sessionCount.Add(1)
	h.sessions.Store(sessionID, session)
	defer h.sessions.Delete(sessionID)

	log.Printf("[terminator] session %d: %s ↔ %s (ALPN=%s)", sessionID, sni, backend, alpn)

	// Bridge streams (blocks until session ends)
	session.bridge()

	log.Printf("[terminator] session %d closed", sessionID)
}

// Shutdown gracefully shuts down the terminator.
func (h *TerminatorHandler) Shutdown(ctx context.Context) error {
	// Cancel context (stops accept loop)
	h.cancel()

	// Close listener
	h.listener.Close()

	// Close transport (and underlying tracker/conn)
	h.transport.Close()

	// Close all sessions
	h.sessions.Range(func(key, val any) bool {
		val.(*terminatorSession).Close()
		return true
	})

	// Wait for all goroutines
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
