module quic-relay

go 1.25.0

require (
	quic-terminator v0.0.0
	github.com/quic-go/quic-go v0.57.1
	golang.org/x/crypto v0.46.0
)

require (
	github.com/klauspost/compress v1.18.2 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace quic-terminator => ./pkg/terminator
