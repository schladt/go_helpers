package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"log"
)

func createKeyPairPEMs() (publicKeyPEM, privateKeyPEM string, err error) {
	reader := rand.Reader
	bitSize := 2048

	// generate key
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return
	}

	// enode private key
	var contentBytes []byte
	if contentBytes, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
		return
	}
	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: contentBytes,
	}
	privBytes := pem.EncodeToMemory(privateKey)

	// encode public key
	if contentBytes, err = x509.MarshalPKIXPublicKey(&key.PublicKey); err != nil {
		return
	}
	var publicKey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: contentBytes,
	}
	pubBytes := pem.EncodeToMemory(publicKey)

	publicKeyPEM = string(pubBytes)
	privateKeyPEM = string(privBytes)
	return
}

// Sign signs data with rsa-sha256
func sign(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, d)
}

// Unsign verifies the message using a rsa-sha256 signature
func verify(publicKey *rsa.PublicKey, message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, d, sig)
}

func main() {

	// create pems
	publicKeyPEM, privateKeyPEM, err := createKeyPairPEMs()
	if err != nil {
		log.Fatalf("Unable to generate key pair: %v", err)
	}

	log.Println(privateKeyPEM)
	log.Println(publicKeyPEM)

	// turn pems back into keys
	privBlock, _ := pem.Decode([]byte(privateKeyPEM))
	privateKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		log.Fatalf("Unable to parse private key: %v", err)
	}

	pubBlock, _ := pem.Decode([]byte(publicKeyPEM))
	publicKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		log.Fatalf("Unable to parse public key: %v", err)
	}

	// sign some data
	signature, err := sign(privateKey.(*rsa.PrivateKey), []byte("This is a signed message"))
	if err != nil {
		log.Fatalf("Unablet to sign message %v", err)
	}

	log.Printf("Signature is %x", signature)

	// verifiy signature
	if err := verify(publicKey.(*rsa.PublicKey), []byte("This is a signed message"), signature); err != nil {
		log.Fatalf("Signature failed: %v", err)
	}

	// verifiy signature
	if err := verify(publicKey.(*rsa.PublicKey), []byte("This is NOT a signed message"), signature); err != nil {
		log.Printf("Signature failed: %v (but that's good thing", err)
	}

	log.Println("Everything checks outs!")

}
