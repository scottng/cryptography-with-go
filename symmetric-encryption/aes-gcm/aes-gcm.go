package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// User interface states
const (
	Init    = 0
	Encrypt = 1
	Decrypt = 2
)

// User messages
const (
	Msg_start = "Enter E to decrypt, D to decrypt"
	Msg_cmd   = "Please enter a valid command (E/D)"
	Msg_enc   = "Enter a message to encrypt: "
	Msg_dec   = "Enter a ciphertext to decrypt: "
)

// Map of ciphertext (b64 string) to key (byte array)
var keymap map[string][]byte = make(map[string][]byte, 100)
var noncemap map[string][]byte = make(map[string][]byte, 100)

func main() {
	state := Init
	fmt.Println(Msg_start)

	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {

		text := scanner.Text()

		switch state {

		case Init:
			// Accept command from user
			if strings.EqualFold("e", text) {
				fmt.Println(Msg_enc)
				state = Encrypt
			} else if strings.EqualFold("d", text) {
				fmt.Println(Msg_dec)
				state = Decrypt
			} else {
				fmt.Println(Msg_cmd)
			}

		case Encrypt:
			// Accept a message to encrypt
			result, error := enc([]byte(text))
			if error != nil {
				fmt.Println(error)
			} else {
				b64_result := b64.StdEncoding.EncodeToString(result)
				fmt.Println(string(b64_result))
			}
			state = Init
			fmt.Println(Msg_start)

		case Decrypt:
			// Accept a cipher to decrypt
			byte_input, _ := b64.StdEncoding.DecodeString(text)
			result, error := dec(byte_input)
			if error != nil {
				fmt.Println(error)
			} else {
				fmt.Println(string(result))
			}
			state = Init
			fmt.Println(Msg_start)
		}
	}
}

// Encryption with AES-128 GCM using Go crypto library
// Authentication tag is appended to end of ciphertext
func enc(payload []byte) ([]byte, error) {

	// Pad payload if needed
	remainder := len(payload) % aes.BlockSize
	if remainder != 0 {
		// Add blocksize - remainder bytes to payload
		desired_size := len(payload) + aes.BlockSize - remainder
		padded_payload := make([]byte, desired_size)
		copy(padded_payload[desired_size-len(payload):], payload)
		payload = padded_payload
	}

	// Generate key
	key := gen(aes.BlockSize)
	block, error := aes.NewCipher(key)
	if error != nil {
		return nil, errors.New("Error")
	}

	// Generate nonce
	nonce := gen(12)

	// Generate a 128-bit block cipher wrapped in GCM
	gcm, error := cipher.NewGCM(block)
	if error != nil {
		return nil, errors.New("Error")
	}

	// Ecrypt
	ciphertext := gcm.Seal(nil, nonce, payload, nil)

	// Store (ciphertext, key) in keymap
	b64_ciphertext := b64.StdEncoding.EncodeToString(ciphertext)
	keymap[string(b64_ciphertext)] = key
	noncemap[string(b64_ciphertext)] = nonce

	return ciphertext, nil
}

// Decryption with AES-128 GCM using Go crypto library
func dec(payload []byte) ([]byte, error) {

	// Check for existing key associated with ciphertext
	b64_payload := b64.StdEncoding.EncodeToString(payload)
	key, key_exists := keymap[b64_payload]
	if !key_exists {
		return payload, errors.New("Key not found")
	}

	// Create new blockmode
	block, error := aes.NewCipher(key)
	if error != nil {
		return nil, errors.New("Error")
	}

	// Wrap blockmode in GCM
	aesgcm, error := cipher.NewGCM(block)
	if error != nil {
		return nil, errors.New("Error")
	}

	nonce, nonce_exists := noncemap[b64_payload]
	if !nonce_exists {
		return payload, errors.New("Nonce not found")
	}

	message, error := aesgcm.Open(nil, nonce, payload, nil)
	if error != nil {
		return nil, errors.New("Error: Invalid tag")
	}

	return message, nil
}

// Key generation of len bytes using crypto/rand
func gen(len int) []byte {
	key := make([]byte, len)
	rand.Read(key)
	return key
}
