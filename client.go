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

// Init connection
func InitClient() *Communicator {
	// Connect to server, setup gob encoder and decoder
	conn, err := net.Dial("tcp", "localhost:"+port)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	gobEnc := gob.NewEncoder(conn)
	gobDec := gob.NewDecoder(conn)

	// Setup suite
	kemID := hpke.KEM_P384_HKDF_SHA384
	kdfID := hpke.KDF_HKDF_SHA384
	aeadID := hpke.AEAD_AES256GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	// Generate client key pair
	publicClient, privateClient, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	// Receive and unmarshal server's public key
	var publicServerBytes []byte
	err = gobDec.Decode(&publicServerBytes)
	if err != nil {
		log.Fatalf("Failed to receive public key: %v", err)
	}
	publicServer, err := kemID.Scheme().UnmarshalBinaryPublicKey(publicServerBytes)
	if err != nil {
		log.Fatalf("Failed to unmarshal public key: %v", err)
	}

	// Send public key to server
	pk, err := publicClient.MarshalBinary()
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}
	err = gobEnc.Encode(pk)
	if err != nil {
		log.Fatalf("Failed to send public key: %v", err)
	}

	// Init sender and receiver
	sender, err := suite.NewSender(publicServer, []byte(info))
	if err != nil {
		log.Fatalf("Failed to create sender: %v", err)
	}
	receiver, err := suite.NewReceiver(privateClient, []byte(info))
	if err != nil {
		log.Fatalf("Failed to create receiver: %v", err)
	}

	// Setup sealer and send encapsulated key to server
	clientEnc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to setup sender: %v", err)
	}
	err = gobEnc.Encode(clientEnc)
	if err != nil {
		log.Fatalf("Failed to send encapsulated key: %v", err)
	}

	// Receive server's encapsulated key
	var serverEnc []byte
	err = gobDec.Decode(&serverEnc)
	if err != nil {
		log.Fatalf("Failed to receive encapsulated key: %v", err)
	}

	// Setup opener from server's encapsulated key
	opener, err := receiver.Setup(serverEnc)
	if err != nil {
		log.Fatalf("Failed to setup receiver: %v", err)
	}

	log.Println("Client initialized")

	return &Communicator{
		conn:   conn,
		gobEnc: gobEnc,
		gobDec: gobDec,
		opener: opener,
		sealer: sealer,
	}
}

func (c *Communicator) ClientChat() {
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
		Body: []byte(ct),
	}

	// Send ciphertext to server
	err = c.gobEnc.Encode(sendPkt)
	if err != nil {
		log.Fatalf("Failed to send ciphertext: %v", err)
	}

	// Receive ciphertext from server
	var recPkt Packet
	err = c.gobDec.Decode(&recPkt)
	if err != nil {
		log.Fatalf("Failed to receive packet: %v", err)
	}

	// Open message
	serverText, err := c.opener.Open(recPkt.Body, []byte(aad))
	if err != nil {
		log.Fatalf("Failed to open message: %v", err)
	}

	// Print plaintext
	fmt.Println("Received message:", string(serverText))
}
