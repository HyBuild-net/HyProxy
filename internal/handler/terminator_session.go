package handler

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"quic-relay/internal/debug"
)

// streamBufPool provides reusable 32KB buffers for stream copying.
var streamBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// LogConfig holds per-direction logging settings.
type LogConfig struct {
	MaxChunks int // Max chunks to log (0 = unlimited when debug enabled)
	Skip      int // Skip first N chunks
	MaxSize   int // Skip chunks larger than this
}

// terminatorSession represents a bridged connection between client and server.
type terminatorSession struct {
	clientConn *quic.Conn
	serverConn *quic.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	closed     atomic.Bool
	wg         sync.WaitGroup

	// Logging config (per direction)
	clientLog *LogConfig
	serverLog *LogConfig
}

func newTerminatorSession(client, server *quic.Conn, cfg *TerminatorConfig) *terminatorSession {
	ctx, cancel := context.WithCancel(context.Background())

	maxSize := cfg.MaxPacketSize
	if maxSize == 0 {
		maxSize = 1024 * 1024 // Default 1MB
	}

	return &terminatorSession{
		clientConn: client,
		serverConn: server,
		ctx:        ctx,
		cancel:     cancel,
		clientLog: &LogConfig{
			MaxChunks: cfg.LogClientPackets,
			Skip:      cfg.SkipClientPackets,
			MaxSize:   maxSize,
		},
		serverLog: &LogConfig{
			MaxChunks: cfg.LogServerPackets,
			Skip:      cfg.SkipServerPackets,
			MaxSize:   maxSize,
		},
	}
}

func (s *terminatorSession) bridge() {
	// Monitor for connection close from either side
	go func() {
		select {
		case <-s.clientConn.Context().Done():
		case <-s.serverConn.Context().Done():
		}
		s.Close()
	}()

	// 4 goroutines for all stream types
	s.wg.Add(4)
	go s.bridgeBidi(s.clientConn, s.serverConn, true)  // Client-initiated
	go s.bridgeBidi(s.serverConn, s.clientConn, false) // Server-initiated
	go s.bridgeUni(s.clientConn, s.serverConn, true)   // Client → Server
	go s.bridgeUni(s.serverConn, s.clientConn, false)  // Server → Client

	s.wg.Wait()
}

func (s *terminatorSession) bridgeBidi(src, dst *quic.Conn, srcIsClient bool) {
	defer s.wg.Done()

	for {
		srcStream, err := src.AcceptStream(s.ctx)
		if err != nil {
			return
		}

		dstStream, err := dst.OpenStream()
		if err != nil {
			srcStream.Close()
			return
		}

		s.wg.Add(1)
		go s.copyBidiStream(srcStream, dstStream, srcIsClient)
	}
}

func (s *terminatorSession) copyBidiStream(src, dst *quic.Stream, srcIsClient bool) {
	defer s.wg.Done()
	defer src.Close()
	defer dst.Close()

	// Log config based on direction
	var fwdLog, revLog *LogConfig
	if srcIsClient {
		fwdLog = s.clientLog // Client → Server
		revLog = s.serverLog // Server → Client
	} else {
		fwdLog = s.serverLog
		revLog = s.clientLog
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// src → dst
	go func() {
		defer wg.Done()
		s.copyStream(dst, src, "[fwd]", fwdLog)
		dst.Close() // Send FIN
	}()

	// dst → src (responses)
	go func() {
		defer wg.Done()
		s.copyStream(src, dst, "[rev]", revLog)
		src.Close()
	}()

	// Wait for BOTH (important for correct cleanup)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Both finished
	case <-s.ctx.Done():
		// Session closed - defer handles cleanup
	}
}

func (s *terminatorSession) bridgeUni(src, dst *quic.Conn, srcIsClient bool) {
	defer s.wg.Done()

	for {
		srcStream, err := src.AcceptUniStream(s.ctx)
		if err != nil {
			return
		}

		dstStream, err := dst.OpenUniStream()
		if err != nil {
			srcStream.CancelRead(0) // Important: cancel source!
			return
		}

		s.wg.Add(1)
		go s.copyUniStream(srcStream, dstStream, srcIsClient)
	}
}

func (s *terminatorSession) copyUniStream(src *quic.ReceiveStream, dst *quic.SendStream, srcIsClient bool) {
	defer s.wg.Done()
	defer src.CancelRead(0) // Cancel source when done
	defer dst.Close()

	logCfg := s.serverLog
	if srcIsClient {
		logCfg = s.clientLog
	}

	s.copyStream(dst, src, "[uni]", logCfg)
}

// copyStream copies data with buffer pooling and optional debug logging.
func (s *terminatorSession) copyStream(dst io.Writer, src io.Reader, prefix string, logCfg *LogConfig) (int64, error) {
	buf := streamBufPool.Get().(*[]byte)
	defer streamBufPool.Put(buf)

	var total int64
	var chunkNum, logged, skipped int

	for {
		n, err := src.Read(*buf)
		if n > 0 {
			// Debug logging with config
			if debug.IsEnabled() && logCfg != nil {
				chunkNum++

				// Skip first N
				if skipped < logCfg.Skip {
					skipped++
				} else if logCfg.MaxChunks == 0 || logged < logCfg.MaxChunks {
					// Skip large chunks
					if logCfg.MaxSize == 0 || n <= logCfg.MaxSize {
						logged++
						debug.LogChunk(prefix, logged, (*buf)[:n])
					}
				}
			}

			nw, werr := dst.Write((*buf)[:n])
			total += int64(nw)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

// Close closes the session and both connections.
func (s *terminatorSession) Close() {
	if !s.closed.Swap(true) {
		s.cancel()
		s.clientConn.CloseWithError(0, "session closed")
		s.serverConn.CloseWithError(0, "session closed")
	}
}
