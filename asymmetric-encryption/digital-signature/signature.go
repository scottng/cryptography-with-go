package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// User interface states
const (
	Path = 0
	Cmd  = 1
	Sig  = 2
	Key  = 3
)

// User messages
const (
	Msg_path = "Enter the path to a file: "
	Msg_cmd  = "Would you like to produce a digital signature (S), or verify one (V)? (S/V)"
	Msg_sig  = "Enter the digital signature: "
	Msg_key  = "Enter the verification key: "
)

func main() {

	var signature []byte
	var key []byte
	var filedata []byte

	state := Path
	fmt.Println(Msg_path)

	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {

		text := scanner.Text()

		switch state {

		case Path:
			// Read file
			fmt.Println("Opening file at " + text)
			filedata, _ = ioutil.ReadFile(string(text))
			fmt.Println(Msg_cmd)
			state = Cmd
		case Cmd:
			// Accept command from user
			if strings.EqualFold("s", text) {
				// Produce the signature and verification key
				signature, key := sign(filedata)

				fmt.Println("Signature: " + hex.EncodeToString(signature))
				fmt.Println("Key: " + hex.EncodeToString(key))

				fmt.Println(Msg_path)
				state = Path
			} else if strings.EqualFold("v", text) {
				fmt.Println(Msg_sig)
				state = Sig
			} else {
				fmt.Println(Msg_cmd)
			}

		case Sig:
			signature, _ = hex.DecodeString(text)
			fmt.Println(Msg_key)
			state = Key
		case Key:
			key, _ = hex.DecodeString(text)
			// Verify signature and key

			verify(filedata, signature, key)

			os.Exit(0)
		}
	}
}

func sign(data []byte) ([]byte, []byte) {
	hash := sha256.Sum256(data)
	privateKey, error := rsa.GenerateKey(rand.Reader, 1024)
	check(error)
	publicKey := privateKey.PublicKey

	parsedPublicKey := x509.MarshalPKCS1PublicKey(&publicKey)
	check(error)

	parsedPrivateKey, error := x509.MarshalPKCS8PrivateKey(privateKey)
	check(error)

	signature, error := enc(hash[:], parsedPrivateKey[:32])
	check(error)

	return signature, parsedPublicKey
}

func verify(data []byte, signature []byte, key []byte) {
	// Compute expected hash
	expected_hash := sha256.Sum256(data)

	// Compute hash
	hash, error := dec(signature, key[:32])
	check(error)

	if hex.EncodeToString(expected_hash[:]) != hex.EncodeToString(hash) {
		fmt.Println("Digital signature verified")
	} else {
		fmt.Println("Failed to verify digital signature")
	}

	os.Exit(0)
}

// Encryption with AES-128 CBC using Go crypto library
func enc(payload []byte, key []byte) ([]byte, error) {

	// Pad payload if needed
	remainder := len(payload) % aes.BlockSize
	if remainder != 0 {
		// Add blocksize - remainder bytes to payload
		desired_size := len(payload) + aes.BlockSize - remainder
		padded_payload := make([]byte, desired_size)
		copy(padded_payload[desired_size-len(payload):], payload)
		payload = padded_payload
	}

	// Create a blockmode and encrypt
	block, error := aes.NewCipher(key)
	check(error)
	ciphertext := make([]byte, aes.BlockSize+len(payload))
	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], payload)

	return ciphertext, nil
}

// Decryption with AES-128 CBC using Go crypto library
func dec(payload []byte, key []byte) ([]byte, error) {

	// Create new blockmode
	block, error := aes.NewCipher(key)
	check(error)

	// Separate iv from ciphertext
	iv := payload[:aes.BlockSize]
	payload = payload[aes.BlockSize:]

	// Decrypt in place
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(payload, payload)

	return payload, nil
}

// Key generation using crypto/rand
func gen(len int) []byte {
	key := make([]byte, len)
	rand.Read(key)
	return key
}

func check(e error) {
	if e != nil {
		fmt.Println(e)
		panic(e)
	}
}
