# Cryptography with Go
This repository contains programs that apply various cryptographic algorithms 
using Go's crypto package. Each Go file is a stand-alone command line program. 

**Disclaimer:** These are programming exercises and are not meant to be
used in any secure application.

## Instructions
To run each program, do `go run [filepath]`

## Symmetric Encryption
### One time pad
* `symmetric-encryption/one-time-pad/otp.go`  

This program allows the user to encrypt and decrypt a message using one time pad.  

One time pad is a perfectly secure symmetric encryption scheme. In one time pad, each character of the plaintext
is XORed with a character in a random key. The key must must be truly random. The key must also be the same size as
 the message and never reused. To generate a truly random key for one time pad, I used Go's crypto/rand package
 which provides a cryptographically secure random number generator.

### Advanced Encryption Scheme (AES)
* `symmetric-encryption/aes-cbc/aes-cbc.go`
* `symmetric-encryption/aes-ctr/aes-ctr.go`
* `symmetric-encryption/aes-gcm/aes-gcm.go`
* `symmetric-encryption/aes-mac/aes-mac.go`  

These programs allow the user to encrypt and decrypt messages of variable size using AES.  

AES is a symmetric block cipher. It is used in VPNs, mobile applications, web applications, etc. to
protect sensitive data. AES supports block sizes of 128, 192, and 256 bits. The AES programs in this 
project use a block size of 128 bits. The AES implementation used is from Go's crypto/aes package.  

Because AES is a block cipher, it can only encrypt a fixed amount of data. To encrypt data of arbitrary
size, AES must be used along with a mode of operation. Go's crypto/cipher package provides several modes.
 In this project, I use CBC, CTR, GCM, and MAC modes from the crypto/cipher package.  

## Asymmetric Encryption
### Public Key Encryption
* `asymmetric-encryption/public-key-encryption/public-key.go`
This program applies public key encryption to an arbitrary file using the RSA implementation provided by Go's
crypto/rsa. It takes as input the path to a file, encrypts and decrypts it, and prints the encryption and decryption time. 
This was made to demonstrate one of the drawbacks of public key encryption: the slow speed of encryption of large files.  

A sample file is provided at `asymmetric-encryption/story.txt`.

### Hybrid Encryption
* `asymmetric-encryption/hybrid-encryption/hybrid.go`  
This program takes as input the path to a file, encrypts and decrypts it, and prints the encryption and decryption time. 
Compare the speed of hybrid key encryption with that of public key encryption.  

A sample file is provided at `asymmetric-encryption/story.txt`.

### Digital Signatures
* `asymmetric-encryption/digital-signature/signature.go`  
This program takes as input the path to a file and outputs a digital signature and verification key on the file.
This program can also verify a digital signature on a file.