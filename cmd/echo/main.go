package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"log"
	"math/big"
	"os"
	"os/signal"
	"syscall"

	"github.com/quic-go/quic-go"
)

const protocol = "quic-echo"

func main() {
	listenAddr := flag.String("listen", ":4433", "Listen address")
	flag.Parse()

	tlsConfig := generateTLSConfig()

	listener, err := quic.ListenAddr(*listenAddr, tlsConfig, &quic.Config{
		MaxIdleTimeout: 60_000_000_000, // 60 seconds in nanoseconds
	})
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	log.Printf("Echo server listening on %s", *listenAddr)
	log.Printf("Protocol: %s", protocol)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConnection(ctx, conn)
	}
}

func handleConnection(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "bye")

	log.Printf("Connection from %s (SNI: %s)",
		conn.RemoteAddr(),
		conn.ConnectionState().TLS.ServerName)

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}

		go handleStream(stream)
	}
}

func handleStream(stream *quic.Stream) {
	defer stream.Close()

	log.Printf("Stream %d opened", stream.StreamID())

	// Echo all data back
	n, err := io.Copy(stream, stream)
	if err != nil {
		log.Printf("Stream %d error: %v", stream.StreamID(), err)
		return
	}

	log.Printf("Stream %d closed (echoed %d bytes)", stream.StreamID(), n)
}

// generateTLSConfig creates a self-signed TLS configuration.
func generateTLSConfig() *tls.Config {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost", "echo.local"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  priv,
		}},
		NextProtos: []string{protocol},
	}
}
