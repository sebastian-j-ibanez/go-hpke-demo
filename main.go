package main

import (
	"encoding/gob"
	"log"
	"net"
	"os"

	"github.com/cloudflare/circl/hpke"
)

const (
	port      = "4444"
	info, aad = "", "" // Empty strings
)

type Communicator struct {
	conn   net.Conn
	gobEnc *gob.Encoder
	gobDec *gob.Decoder
	opener hpke.Opener
	sealer hpke.Sealer
}

// Packet types
type PacketType int

const (
	EncryptedPacket PacketType = iota
)

type Packet struct {
	Type PacketType
	Body []byte
}

func main() {
	var communicator *Communicator
	if len(os.Args) > 1 && os.Args[1] == "server" {
		communicator = InitServer()
		if communicator == nil {
			log.Fatalf("Failed to initialize server")
		}
		communicator.ServerChat()
	} else {
		communicator = InitClient()
		if communicator == nil {
			log.Fatalf("Failed to initialize client")
		}
		communicator.ClientChat()
	}
}
