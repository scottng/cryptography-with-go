package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	Tag     = 3
)

// User messages
const (
	Msg_start = "Enter E to encrypt and generate tag, D to decrypt, V to verify tag"
	Msg_cmd   = "Please enter a valid command (E/D/V)"
	Msg_enc   = "Enter a message to encrypt: "
	Msg_dec   = "Enter a ciphertext to decrypt: "
	Msg_tag   = "Enter a message and a tag, separated by a space (e.g. Hello, World! daKb6r2wjBuY0uiI+vQm3yqOchvnjaiioqUO5kXpAo0=): "
)

// Map of ciphertext (b64 string) to key (byte array)
var keymap map[string][]byte = make(map[string][]byte, 100)
var msgtokey map[string][]byte = make(map[string][]byte, 100)

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
			} else if strings.EqualFold("v", text) {
				fmt.Println(Msg_tag)
				state = Tag
			} else {
				fmt.Println(Msg_cmd)
			}

		case Encrypt:
			// Accept a message to encrypt
			ciphertext, tag, error := enc([]byte(text), text)
			if error != nil {
				fmt.Println(error)
			} else {
				b64_ciphertext := b64.StdEncoding.EncodeToString(ciphertext)
				fmt.Println("Ciphertext: " + string(b64_ciphertext))
				b64_tag := b64.StdEncoding.EncodeToString(tag)
				fmt.Println("Tag: " + b64_tag)

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

		case Tag:
			fields := strings.Fields(text)
			message := strings.Join(fields[:len(fields)-1], " ")
			tag := fields[len(fields)-1]

			key, exists := msgtokey[message]
			if !exists {
				fmt.Println("Key not found")
				state = Init
				fmt.Println(Msg_start)
				break
			}

			byte_tag, error := b64.StdEncoding.DecodeString(tag)
			if error != nil {
				fmt.Println("Did not decode tag")
				state = Init
				fmt.Println(Msg_start)
				break
			}

			// fmt.Println(byte_tag)
			// fmt.Println(key)
			// fmt.Println(message)

			valid := validate_mac([]byte(message), byte_tag, key)
			if valid {
				fmt.Println("Valid tag")
			} else {
				fmt.Println("Invalid tag")
			}

			state = Init
			fmt.Println(Msg_start)
		}
	}
}

// Encryption with AES-128 CBC using Go crypto library
func enc(payload []byte, text string) ([]byte, []byte, error) {

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
		return nil, nil, errors.New("Error")
	}

	// Create a blockmode and encrypt
	ciphertext := make([]byte, aes.BlockSize+len(payload))
	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], payload)

	// Store (ciphertext, key) in keymap
	b64_ciphertext := b64.StdEncoding.EncodeToString(ciphertext)
	keymap[string(b64_ciphertext)] = key

	msgtokey[text] = key

	// Generate MAC
	hmac_hash := hmac.New(sha256.New, key)
	hmac_hash.Write([]byte(text))
	mac := hmac_hash.Sum(nil)

	return ciphertext, mac, nil
}

// Decryption with AES-128 CBC using Go crypto library
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

	// Separate iv from ciphertext
	iv := payload[:aes.BlockSize]
	payload = payload[aes.BlockSize:]

	// Decrypt in place
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(payload, payload)

	return payload, nil
}

// Key generation of len bytes using crypto/rand
func gen(len int) []byte {
	key := make([]byte, len)
	rand.Read(key)
	return key
}

// Check if MAC is valid
func validate_mac(message, mac, key []byte) bool {
	hmac_hash := hmac.New(sha256.New, key)
	hmac_hash.Write(message)
	return hmac.Equal(mac, hmac_hash.Sum(nil))
}
