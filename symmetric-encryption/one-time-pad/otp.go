package main

import (
	"bufio"
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
			result, error := otp_enc([]byte(text))
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
			result, error := otp_dec(byte_input)
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

// Encryption with one time pad
func otp_enc(payload []byte) ([]byte, error) {
	len := len(payload)
	key := gen(len)

	ciphertext := make([]byte, len)

	for i := 0; i < len; i++ {
		ciphertext[i] = payload[i] ^ key[i]
	}

	b64_ciphertext := b64.StdEncoding.EncodeToString(ciphertext)
	keymap[string(b64_ciphertext)] = key

	return ciphertext, nil
}

// Encryption with one time pad
func otp_dec(payload []byte) ([]byte, error) {

	// Check for existing key associated with ciphertext
	key, exists := keymap[b64.StdEncoding.EncodeToString(payload)]
	if !exists {
		return payload, errors.New("Key not found")
	}

	len := len(payload)
	message := make([]byte, len)
	for i := 0; i < len; i++ {
		message[i] = payload[i] ^ key[i]
	}

	return message, nil
}

// Key generation using crypto/rand
func gen(len int) []byte {
	key := make([]byte, len)
	rand.Read(key)
	return key
}
