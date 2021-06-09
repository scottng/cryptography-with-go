package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

		// Sender encrypts data
		encryptStart := time.Now()
		ciphertext, privateKey := sender(data)
		encryptDuration := time.Since(encryptStart)
		fmt.Println("Encryption time: " + encryptDuration.String())

		// Receiver decrypts ciphertext
		decryptStart := time.Now()
		receiver(ciphertext, privateKey)
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

func sender(message []byte) ([][]byte, []*rsa.PrivateKey) {

	// for each 245-byte block in data, encrypt the block
	n := len(message) // n: number of bytes in message
	BLOCK_SIZE := 100
	encryptedBlocksSize := n / BLOCK_SIZE
	if n%BLOCK_SIZE > 0 {
		encryptedBlocksSize++
	}

	encryptedBlocks := make([][]byte, encryptedBlocksSize)
	blockKeys := make([]*rsa.PrivateKey, encryptedBlocksSize)
	for i := 0; i < n; {

		end := i + BLOCK_SIZE
		if end > n {
			end = n
		}
		currBlock := message[i:end]

		blockCipher, blockPrivateKey := encryptBlock(currBlock)

		encryptedBlocks = append(encryptedBlocks, blockCipher)
		blockKeys = append(blockKeys, blockPrivateKey)

		i = end
	}

	return encryptedBlocks, blockKeys

}

func encryptBlock(block []byte) ([]byte, *rsa.PrivateKey) {
	privateKey, error := rsa.GenerateKey(rand.Reader, 2048)
	check(error)

	publicKey := privateKey.PublicKey
	ciphertext, error := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		block,
		nil,
	)
	check(error)

	return ciphertext, privateKey
}

func receiver(encryptedBlocks [][]byte, blockKeys []*rsa.PrivateKey) []byte {
	message := make([]byte, 0)

	for i := 0; i < len(encryptedBlocks); i++ {

		if len(encryptedBlocks[i]) == 0 {
			continue
		}

		blockMessage := decryptBlock(encryptedBlocks[i], blockKeys[i])

		message = append(message, blockMessage...)
	}

	return message
}

func decryptBlock(ciphertext []byte, privateKey *rsa.PrivateKey) []byte {
	message, error := privateKey.Decrypt(
		nil,
		ciphertext,
		&rsa.OAEPOptions{Hash: crypto.SHA256},
	)
	check(error)

	return message
}
