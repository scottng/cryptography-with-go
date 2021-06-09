package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

func main() {

	fmt.Println("Enter a file path to encrypt: ")
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {

		text := scanner.Text()

		// Read file
		fmt.Println("Opening file at " + text)
		data, error := ioutil.ReadFile(string(text))
		check(error)

		// Receiver generates public/private key
		publicKey, privateKey := receiver_gen_public_key()

		// Sender encrypts data
		encryptStart := time.Now()
		ciphertext, encryptedSymmetricKey := sender(data, &publicKey)
		encryptDuration := time.Since(encryptStart)
		fmt.Println("Encryption time: " + encryptDuration.String())

		// Receiver decrypts ciphertext
		decryptStart := time.Now()
		receiver(&privateKey, encryptedSymmetricKey, ciphertext)
		decryptDuration := time.Since(decryptStart)
		fmt.Println("Decryption time: " + decryptDuration.String())

		fmt.Println("Enter a file path to encrypt: ")
	}
}

func check(e error) {
	if e != nil {
		fmt.Println(e)
		panic(e)
	}
}

func sender(message []byte, publicKey *rsa.PublicKey) ([]byte, []byte) {
	// Obtain receiver's public key

	// Generate symmetric key
	symmetricKey := gen(aes.BlockSize)

	// Encrypt message using symmetric key
	ciphertext, error := enc(message, symmetricKey)
	check(error)

	// Convert RSA public key to PKCS #1
	parsedPublicKey := x509.MarshalPKCS1PublicKey(publicKey)[:32]

	// Encrypt symmetric key using receiver's public key
	encryptedSymmetricKey, error := enc(symmetricKey, parsedPublicKey)
	check(error)

	return ciphertext, encryptedSymmetricKey
}

func receiver(privateKey *rsa.PrivateKey, encryptedSymmetricKey []byte, ciphertext []byte) []byte {
	// use receiver's private key to decrypt the symmetric key from sender
	// use symmetric key to decrypt the ciphertext

	parsedPrivateKey, error := x509.MarshalPKCS8PrivateKey(privateKey)
	check(error)

	symmetricKey, error := dec(encryptedSymmetricKey, parsedPrivateKey[:32])
	check(error)

	message, error := dec(ciphertext, symmetricKey)

	return message
}

func receiver_gen_public_key() (rsa.PublicKey, rsa.PrivateKey) {
	privateKey, error := rsa.GenerateKey(rand.Reader, 2048)
	check(error)

	publicKey := privateKey.PublicKey

	return publicKey, *privateKey
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

// Key generation of len bytes using crypto/rand
func gen(len int) []byte {
	key := make([]byte, len)
	rand.Read(key)
	return key
}
