/*
Author: Harry Singh
Script to encrypt/decrypt a file with a given master key
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

func main() {
	fileName := os.Args[1]              // First CLI argument
	extension := filepath.Ext(fileName) // Extract file extension
	encKey := os.Args[2]                // master key - the 2nd CLI argument
	fmt.Println("Enter key again: ")
	var encKey2 string
	fmt.Scanln(&encKey2)
	if encKey != encKey2 {
		fmt.Println("Error: Keys did not match.")
		os.Exit(1)
	}
	content, err := ioutil.ReadFile(fileName) // content is a []byte object
	handleError(err)
	if extension == ".txt" { // Encrypt if txt
		encryptedData, err := encryptData([]byte(encKey), content) // Convert string key to byte slice
		writeENC(encryptedData, fileName)
		handleError(err)
	} else if extension == ".enc" { // Decrypt if enc
		decryptedData, err := decryptData([]byte(encKey), content)
		handleError(err)
		writeTXT(decryptedData, fileName)
	} else {
		// Reliance on extensions can be eliminated altogether but the goal here was a very basic service
		fmt.Println("Error: The file extension should either be txt or enc")
		os.Exit(1)
	}

	handleError(err)

	handleError(err)

}

func deriveKey(key, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	key, err := scrypt.Key(key, salt, 1048576, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

func encryptData(key []byte, data []byte) ([]byte, error) {
	key, salt, err := deriveKey(key, nil)
	handleError(err)
	blockCipher, err := aes.NewCipher(key) // AES is an advanced symmetric-key encryption algorithm
	handleError(err)
	gcm, err := cipher.NewGCM(blockCipher) // Using the  Galois Counter Mode (GCM) for wrapping the block cipher so it encrypts more than 16 bytes
	handleError(err)
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	ciphertext = append(ciphertext, salt...)
	return ciphertext, nil
}

func decryptData(key []byte, data []byte) ([]byte, error) {
	salt, data := data[len(data)-32:], data[:len(data)-32]
	key, _, err := deriveKey(key, salt)
	handleError(err)
	blockCipher, err := aes.NewCipher(key)
	handleError(err)
	gcm, err := cipher.NewGCM(blockCipher)
	handleError(err)
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	handleError(err)
	return plaintext, nil
}

func writeENC(data []byte, fileName string) {
	sec := time.Now().Format("20060102150405") // Append timestamp to filename for uniqueness
	fileName = strings.TrimSuffix(fileName, ".txt")
	f, err := os.Create(fileName + "_" + sec + ".enc")
	handleError(err)
	l, err := f.Write(data)
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}
	fmt.Println(l, "bytes written successfully. Encryption complete!")
	err = f.Close()
	handleError(err)
}

func writeTXT(data []byte, fileName string) {
	sec := time.Now().Format("20060102150405")
	fileName = strings.TrimSuffix(fileName, ".enc")
	f, err := os.Create(fileName + "_" + sec + ".txt")
	handleError(err)
	l, err := f.Write(data)
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}
	fmt.Println(l, "bytes written successfully. Decryption complete!")
	err = f.Close()
	handleError(err)
}

func handleError(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	return
}
