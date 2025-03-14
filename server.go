package main

import (
	"bufio"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cloudflare/circl/hpke"
)

// Await connection
func InitServer() *Communicator {
	// Listen for connection over port
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", port, err)

	}

	conn, err := lis.Accept()
	if err != nil {
		log.Fatalf("Failed to accept connection: %v", err)
		return nil
	}
	gobEnc := gob.NewEncoder(conn)
	gobDec := gob.NewDecoder(conn)

	// HPKE suite is a domain parameter.
	kemID := hpke.KEM_P384_HKDF_SHA384
	kdfID := hpke.KDF_HKDF_SHA384
	aeadID := hpke.AEAD_AES256GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	// Generate key pair
	publicServer, privateServer, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
		return nil
	}

	// Marhsall and send public key
	b, err := publicServer.MarshalBinary()
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
		return nil
	}
	err = gobEnc.Encode(b)
	if err != nil {
		log.Fatalf("Failed to send public key: %v", err)
		return nil
	}

	// Receive and unmarshal client's public key
	var publicClientBytes []byte
	err = gobDec.Decode(&publicClientBytes)
	if err != nil {
		log.Fatalf("Failed to receive public key: %v", err)
		return nil
	}
	publicClient, err := kemID.Scheme().UnmarshalBinaryPublicKey(publicClientBytes)
	if err != nil {
		log.Fatalf("Failed to unmarshal public key: %v", err)
		return nil
	}

	// Init sender and receiver
	sender, err := suite.NewSender(publicClient, []byte(info))
	if err != nil {
		log.Fatalf("Failed to create sender: %v", err)
		return nil
	}
	receiver, err := suite.NewReceiver(privateServer, []byte(info))
	if err != nil {
		log.Fatalf("Failed to create receiver: %v", err)
		return nil
	}

	// Receive client's encapsulated key
	var clientEnc []byte
	err = gobDec.Decode(&clientEnc)
	if err != nil {
		log.Fatalf("Failed to receive encrypted message: %v", err)
	}

	// Setup sealer and send encapsulated key to client
	serverEnc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to setup sender: %v", err)
		return nil
	}
	err = gobEnc.Encode(serverEnc)
	if err != nil {
		log.Fatalf("Failed to send encapsulated key: %v", err)
		return nil
	}

	// Setup opener from client's encapsulated key
	opener, err := receiver.Setup(clientEnc)
	if err != nil {
		log.Fatalf("Failed to setup receiver: %v", err)
	}

	log.Println("Server initialized")

	return &Communicator{
		conn:   conn,
		gobEnc: gobEnc,
		gobDec: gobDec,
		opener: opener,
		sealer: sealer,
	}
}

func (c *Communicator) ServerChat() {
	var recPkt Packet
	err := c.gobDec.Decode(&recPkt)
	if err != nil {
		log.Fatalf("Failed to receive packet: %v", err)
	}

	// Receive ciphertext from client
	// var ct []byte
	// err = c.gobDec.Decode(&ct)
	// if err != nil {
	// 	log.Fatalf("Failed to receive ciphertext: %v", err)
	// }

	// Open message
	serverText, err := c.opener.Open(recPkt.Body, []byte(aad))
	if err != nil {
		log.Fatalf("Failed to open message: %v", err)
	}

	// Print plaintext
	fmt.Println("Received message:", string(serverText))

	// Read message from stdin
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter message: ")
	pt, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Failed to read message: %v", err)
	}

	// Seal message
	ct, err := c.sealer.Seal([]byte(pt), []byte(aad))
	if err != nil {
		log.Fatalf("Failed to seal message: %v", err)
	}

	sendPkt := Packet{
		Type: EncryptedPacket,
		Body: ct,
	}

	// Send ciphertext to client
	err = c.gobEnc.Encode(sendPkt)
	if err != nil {
		log.Fatalf("Failed to send ciphertext: %v", err)
	}
}
