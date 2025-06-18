/*
MIT License
Copyright (c) 2024 Kezia Sharnoff


This program decrypts or encrypts a file with AES 256 encryption. It uses a
single salt that is predetermined, as written in the function named
keyGeneration.

A single salt for all encryption has the upside that it is impossible to lose
the salt, something that would make the file unable to be decrypted.
Theoretically, the downside is that when re-encrypting the same file, a
malicious actor can see where any changes were. However, there is randomness
in this encryption so it does not have that downside.

This can take in a file of any type. The encryption will be written to a .txt
file. Then when decrypted, it will turn back to its original file type. If the
inputted encrypted file starts off at .yaml, the decrypted will remain .yaml.
This behavior to do with .yaml is because of my password manager,
github.com/ksharnoff/pass.
*/

package main

import (
	// main
	"errors"
	"fmt"
	"os"
	"strings"

	// random two digit generation
	mathRand "math/rand"
	"strconv"
	"time"

	// encrypting things
	"crypto/aes"
	"crypto/cipher"
	"golang.org/x/crypto/argon2"

	// iv generation
	cryptRand "crypto/rand"
	"io"
)

func main() {
	fmt.Println("-----------")
	fmt.Println("Hello! These will be the steps:")
	fmt.Println("\t- You'll write the file name")
	fmt.Println("\t- You'll chose to encrypt or decrypt")
	fmt.Println("\t- You'll write your password")
	fmt.Println("A new file will have been made! Woo!")
	fmt.Println("Type 0 for help.")
	fmt.Println("Type your answers, then hit enter")
	fmt.Println("-----------")
	skipLine()

	var fileName string
	fmt.Print("What is the name of the file?: ")
	fmt.Scan(&fileName)

	for fileName == "0" {
		skipLine()
		fmt.Println("Make sure the file is in the same folder as this program!")
		fmt.Println("Just write exactly what the file is named")
		fmt.Println("Make sure that you include the extension!")
		fmt.Println("\taka 'testing.pdf' not just 'testing'")
		fmt.Println("Also make sure that there is no spaces in the file name!")
		skipLine()
		fmt.Print("What is the name of the file?: ")
		fmt.Scan(&fileName)
	}
	if doesFileExist(fileName) {
		fmt.Println("That file exists!")
	} else {
		printAndExit("Error! The chosen file does not exist")
	}
	// from this point on, the file chosen does exist

	action := 0
	for (action != 1) && (action != 2) {
		skipLine()
		fmt.Print("Decrypt (1) or encrypt (2)?: ")
		fmt.Scan(&action)
		if action == 0 {
			skipLine()
			fmt.Println("Decrypt means to decode, make it a readable file.")
			fmt.Println("Encrypt does the opposite, it scrambles it.")
			fmt.Println("If you chose decrypt and the file is not encrypted, the program will fail.")
		}
	}

	fmt.Println("\nAfter you press return on your password, it will disappear!")
	password := "0"
	for password == "0" {
		skipLine()
		fmt.Println("What is your password?: ")
		fmt.Scan(&password)
		fmt.Print("\033[F\r", strings.Repeat(" ", len(password))) // writes over the password so its not in the terminal anymore
		if password == "0" {
			skipLine()
			if action == 1 {
				fmt.Println("This is the password that you used to encrypt this file previously.")
				fmt.Println("If you do not know it, the file cannot be decrypted.")
			} else {
				fmt.Println("This will be the password you must remember to get this file back.")
				fmt.Println("Maybe write it down somewhere?")
			}
		}
		if len(password) < 6 {
			fmt.Println("That password is too short, please use at least six characters!")
			password = "0"
		}
	}

	fmt.Println("\nTHINGS ARE HAPPENING - DO NOT QUIT THE PROGRAM")

	input, inputErr := os.ReadFile(fileName) // input is a [] of bytes

	if inputErr != nil {
		printAndExit("Error in os.ReadFile " + inputErr.Error())
	}

	if len(input) == 0 {
		printAndExit("Error! That file is empty")
	}

	ciphBlock := keyGeneration(password)

	// assuming fileName input was testingtest.pdf
	// new encrypted file should be: e-testingtest.pdf.txt
	// or if decrypted: d-e-testingtest.pdf

	var outputToWrite []byte
	var newFileName string

	if action == 1 { // decrypts
		outputToWrite = decrypt(input, ciphBlock)
		newFileName = "d"
	} else if action == 2 { // encrypts
		outputToWrite = encrypt(input, ciphBlock)
		newFileName = "e"
	} else { // should never be this!
		printAndExit("Error! Encrypt or decrypt were not chosen")
	}

	newFileName += fmt.Sprint("-" + fileName)

	// if the newFileName already exists then it adds a random two digits to the start
	// so it would look like: 38e-testingtest.pdf.txt
	for (doesFileExist(newFileName)) || (doesFileExist(newFileName + ".txt")) {
		newFileName = strconv.Itoa(randNum()) + newFileName
	}

	// if decrypting, remove the .txt added when encrypted, making the file go
	// back to its original status of .pdf, etc
	if action == 1 {
		beforeTxt, foundTxt := strings.CutSuffix(newFileName, ".txt")
		if foundTxt { // if newFileName did end in ".txt"
			newFileName = beforeTxt
		} else { // it shouldn't get to this else, if it was encrypted by crypter!

			// if was encrypted by my pass manager will be 'testing.yaml', this will leave it as .yaml
			_, foundYaml := strings.CutSuffix(newFileName, ".yaml")

			if !foundYaml { // the encrypted file didn't end in .txt or .yaml
				fmt.Println("Are you sure that you meant to Decrypt? Decrypt (1) or encrypt (2)?: ")
				fmt.Scan(&action)

				if action == 1 {
					newFileName += ".txt"
					fmt.Println("THINGS ARE HAPPENING - DO NOT QUIT THE PROGRAM")
				} else {
					printAndExit("Error! The file inputted wasn't encrypted by crypter in a format that can guarantee a file type! \nAnd you changed your mind about decrypting!")
				}
			}
		}
	} else {
		// if encrypting, add a .txt so it becomes a txt file
		newFileName += ".txt"
	}

	// 0600 is the permissions that only this user can read, write, exec this file
	writeErr := os.WriteFile(newFileName+".tmp", outputToWrite, 0700)

	if writeErr != nil {
		printAndExit("Error in os.WriteFile " + writeErr.Error())
	}

	// only will happen if the previous writing succeeded, a fail safe
	os.Rename(newFileName+".tmp", newFileName)

	fmt.Println("All is done!")

	if action == 1 { // if decrypting
		fmt.Println("By the way, if you got the password wrong, the file will be gibberish!")
	}
	fmt.Println("-----------")
}

func skipLine() {
	fmt.Print("\n")
}

func printAndExit(error string) {
	fmt.Println(error)
	os.Exit(1)
}

// returns bool for if a file exists (within the
// directory / folder that this program is being run)
func doesFileExist(fileName string) bool {
	// os.Stat is a function to get info about file, and can return and error
	// that the file doesn't exist
	_, err := os.Stat(fileName)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

// Returns random int between 0 and 99, after seeding using the Unix time in
// nanoseconds and the processing ID. This is just used for making unique
// file names and therefore does not need to be cryptographically secure.
func randNum() int {
	mathRand.Seed(time.Now().UnixNano() ^ int64(os.Getpid()))
	return mathRand.Intn(99)
}

// Input: the user's password.
// Output: cipher block made from a key from the password.
func keyGeneration(password string) cipher.Block {
	if len([]byte(password)) < 1 {
		printAndExit("Error! The password for key generation is too short")
	}

	// The salt is going to be the same every time.
	salt := []byte("zxcvbnmlkjhgfdsa")

	// pass params: 4, 2048*1024, 4, 32 -- takes about 2 seconds
	// crypter params: 2, 64*1024, 4, 32
	// REDUCED crypter params: 1, 64*1024, 4, 32
	// password, salt, time, memory, threads, keyLen
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	ciphBlock, err := aes.NewCipher(key)

	if err != nil {
		printAndExit("Error in key generation!" + err.Error())
	}
	return ciphBlock
}

// Input: the plaintext slice and a cipher block.
// Return: the encrypted bytes.
// Encrypts a slice of bytes using the cipher block (from the key)
func encrypt(plaintext []byte, ciphBlock cipher.Block) []byte {
	// adds padding in form of "\n"
	if len(plaintext)%aes.BlockSize != 0 {
		for i := len(plaintext) % aes.BlockSize; i < aes.BlockSize; i++ {
			// 0x0A = []byte("\n")
			plaintext = append(plaintext, 0x0A)
		}
	}
	encrypt := make([]byte, aes.BlockSize+len(plaintext))

	iv := encrypt[:aes.BlockSize]

	_, err := io.ReadFull(cryptRand.Reader, iv)

	if err != nil {
		printAndExit("Error in crypto rand IV generation! " + err.Error())
	}

	encryptBlock := cipher.NewCBCEncrypter(ciphBlock, iv)

	encryptBlock.CryptBlocks(encrypt[aes.BlockSize:], plaintext)

	return encrypt
}

// Inputs the encrypted slice and a cipher block made from the same original
// password.
// Returns a decrypted slice.
// Decrypts the encrypted bytes using the cipher block. If the cipher block
// was made incorrectly, this will panic.
// If the decryption failed (wrong password), nonsense will be returned.
func decrypt(encrypted []byte, ciphBlock cipher.Block) []byte {
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	decryptBlock := cipher.NewCBCDecrypter(ciphBlock, iv)

	decrypt := make([]byte, len(encrypted))

	decryptBlock.CryptBlocks(decrypt, encrypted)

	return decrypt
}
