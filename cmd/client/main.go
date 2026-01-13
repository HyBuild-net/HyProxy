package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/quic-go/quic-go"
)

const protocol = "quic-echo"

func main() {
	target := flag.String("target", "localhost:4433", "Target address")
	sni := flag.String("sni", "echo.local", "SNI hostname")
	message := flag.String("message", "Hello HyProxy!", "Message to send")
	flag.Parse()

	fmt.Println("========================================")
	fmt.Printf("  HyProxy Client\n")
	fmt.Printf("  Target: %s\n", *target)
	fmt.Printf("  SNI:    %s\n", *sni)
	fmt.Println("========================================")

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         *sni,
		NextProtos:         []string{protocol},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Printf("Connecting to %s...", *target)
	conn, err := quic.DialAddr(ctx, *target, tlsConfig, &quic.Config{
		MaxIdleTimeout: 30_000_000_000, // 30 seconds
	})
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	log.Printf("Connected! Remote: %s", conn.RemoteAddr())

	// Open a stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	log.Printf("Stream %d opened", stream.StreamID())

	// Send message
	log.Printf("Sending: %s", *message)
	_, err = stream.Write([]byte(*message))
	if err != nil {
		log.Fatalf("Failed to send: %v", err)
	}

	// Close write side to signal we're done sending
	stream.Close()

	// Read response
	response, err := io.ReadAll(stream)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	fmt.Println("----------------------------------------")
	fmt.Printf("Response: %s\n", string(response))
	fmt.Println("----------------------------------------")

	if string(response) == *message {
		fmt.Println("SUCCESS: Echo verified!")
	} else {
		fmt.Println("MISMATCH: Response differs from sent message")
	}
}
