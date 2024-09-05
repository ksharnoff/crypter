/*
This program decrypts or encrypts a file with AES 256 encryption. It uses a 
randomly generated salt that is different each time. If it is encrypting, it 
generates a new salt and writes to the beginning of the file. If it is 
decrypting, it reads the salt from the file.

Theoretically, the upside is that when re-encrypting the same file, a  
malicious actor cannot see where any changes were. However, there is 
randomness in this encryption so even when the salt is the same, there is not 
this upside. A single salt for all encryption has the downside that if the salt 
is lost or unable to be read, it would be impossible to decrypt. It is like 
needing two passwords to the file and the user never knows one of them.

This can take in a file of any type. The encryption will be written to a .txt 
file. Then when decrypted, it will turn back to its original file type. If the 
inputted encrypted file starts off at .yaml, the decrypted will remain .yaml. 
This behavoir to do with .yaml is because of my password manager, 
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
	fmt.Print("-----------\nHello! These will be the steps:\n\tYou'll give the file name\n\tYou'll chose to encrypt or decrypt\n\tYou'll give your password\nA new file will have been made! Wooo!\nType 0 for help.\nType your answers, then hit enter\n-----------\n")
	skipLine()

	var fileName string
	fmt.Print("What is the name of the file?: ")
	fmt.Scan(&fileName)

	for fileName == "0" {
		skipLine()
		fmt.Println("Make sure the file is in the same folder as this program!\nJust write exactly what the file is named\nMake sure that you include the extension!\n\taka 'testing.pdf' not just 'testing'\nAlso make sure that there is no spaces in the file name!")
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
		fmt.Print("Decyrypt (1) or encrypt (2)?: ")
		fmt.Scan(&action)
		if action == 0 {
			skipLine()
			fmt.Println("Decrypt means to decode, make it a readable file.\nEncrypt does the opposite, it scrambles it.\nIf you chose decrypt and the file is not encrypted, the program will fail.")
		}
	}

	fmt.Println("\nAfter you press enter on your password, it will disappear!")
	password := "0"
	for password == "0" {
		skipLine()
		fmt.Println("What is your password?: ")
		fmt.Scan(&password)
		fmt.Print("\033[F\r", strings.Repeat(" ", len(password))) // writes over the password so its not in the terminal anymore
		if password == "0" {
			skipLine()
			if action == 1 {
				fmt.Println("This is the password that you used to encrypt this file previously.\nIf you do not know it, the file cannot be decrypted.")
			} else {
				fmt.Println("This will be the password you must remember to get this file back.\nMaybe write it down somewhere?")
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

	var salt []byte

	if action == 1 { // if decrypted
		salt, input = saltShaker(input, true)
	} else if action == 2 { // if encrypted
		salt, input = saltShaker(input, false)
	}

	ciphBlock := keyGeneration(password, salt)

	// assuming fileName input was testingtest.pdf
	// new encrypted file should be: e-testingtest.df.txt
	// or if decrypted: d-e-testingtest.pdfs

	var outputToWrite []byte
	var newFileName string

	if action == 1 { // decrypts
		outputToWrite = decrypt(input, ciphBlock)
		newFileName = "d"
	} else if action == 2 { // encrypts
		outputToWrite = salt 
		outputToWrite = append(outputToWrite, encrypt(input, ciphBlock)...)
		newFileName = "e"
	} else { // should never be this! maybe get rid of this check?
		printAndExit("Error! Encrypt or decrypt were not chosen")
	}

	newFileName += fmt.Sprint("-" + fileName)

	// if the newFileName already exists then it adds a random two digits to the start
	// so it would look like: 38e-testingtest.yaml.txt
	for (doesFileExist(newFileName)) || (doesFileExist(newFileName + ".txt")) { // hopefully shouldn't need to repeat!
		newFileName = strconv.Itoa(randNum()) + newFileName // adds a random two digits to the start
	}

	if action == 1 { // if decrypting, remove the .txt added when encrypted, making the file go back to its original status of .pdf, etc
		beforeTxt, foundTxt := strings.CutSuffix(newFileName, ".txt")
		if foundTxt { // if newFileName did end in ".txt"
			newFileName = beforeTxt
		} else { // it shouldn't get to this else, if it was encrypted by crypter!
			_, foundYaml := strings.CutSuffix(newFileName, ".yaml") // if was encrypted by my pass manager will be 'testing.yaml', this will leave it as .yaml

			if !foundYaml { // the encrypted file didn't end in .txt or .yaml
				fmt.Println("Are you sure that you meant to Decrypt? Decyrypt (1) or encrypt (2)?: ") // at this point it will have already decrypted
				fmt.Scan(&action)

				if action == 1 {
					newFileName += ".txt"
					fmt.Println("THINGS ARE HAPPENING - DO NOT QUIT THE PROGRAM")
				} else {
					printAndExit("Error! The file inputted wasn't encrypted by crypter in a format that can guarantee a file type! \nAnd you changed your mind about decrypting!")
				}
			}
		}
	} else { // if encrypting, add a .txt so it becomes a txt file
		newFileName += ".txt"
	}

	writeErr := os.WriteFile(newFileName + ".tmp", outputToWrite, 0600) // 0600 is  permissions that only this user can read/write/excet to this file

	if writeErr != nil {
		printAndExit("Error in os.WriteFile " + writeErr.Error())
	}

	os.Rename(newFileName + ".tmp", newFileName) // only will do this if previous writing worked

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
	_, err := os.Stat(fileName)         // os.Stat is a function to get info about file, and can return error
	if errors.Is(err, os.ErrNotExist) { // if the error is that the file doesn't exist
		return false
	}
	return true
}

// Returns random number, not cryptographicaly secure
func randNum() int {
	mathRand.Seed(time.Now().UnixNano() ^ int64(os.Getpid()))
	return mathRand.Intn(99) // should return number less than 99
}

// I named it saltShaker cause it's funny. Better name would be makeSalt
// Takes the input slice of bytes from the file
// If decrypt is true, then the salt must be extracted from the beginning of the file
// If decrypt is false, a new salt must be generated
// First variable returned is the salt, second is the contents of the file. 
func saltShaker(input []byte, decrypt bool) ([]byte, []byte) {
	if decrypt { // so take the salt from the beginning of the file
		if len(input) < 31 {
			printAndExit("Error in getting salt! File inputed too short")
		}
		return input[:32], input[32:]
	}

	salt := make([]byte, 32)
	_, err := cryptRand.Read(salt)

	if err != nil {
		printAndExit("Error in making salt! " + err.Error())
	}
	return salt, input
}

// Makes a key, then a cipher block
func keyGeneration(password string, salt []byte) cipher.Block {
	if len([]byte(password)) < 1 {
		printAndExit("Error! The password for key generation is too short")
	}

	// pass params: 4, 2048*1024, 4, 32 -- takes about 2 seconds
	// func IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32)
	// crypter params: 2, 64*1024, 4, 32
	key := argon2.IDKey([]byte(password), salt, 2, 64*1024, 4, 32)

	ciphBlock, err := aes.NewCipher(key)

	if err != nil {
		printAndExit("Error in key generation!" + err.Error())
	}
	return ciphBlock
}

// returns an encrypted slice of bytes
func encrypt(plaintext []byte, ciphBlock cipher.Block) []byte {
	// adds padding in form of "\n"
	if len(plaintext) % aes.BlockSize != 0 {
		for i := len(plaintext) % aes.BlockSize; i < aes.BlockSize; i++ {
			plaintext = append(plaintext, 0x0A) // 0x0A = []byte("\n")
		}
	}
	fmt.Println(aes.BlockSize)
	encrypt := make([]byte, aes.BlockSize + len(plaintext))

	iv := encrypt[:aes.BlockSize]

	_, err := io.ReadFull(cryptRand.Reader, iv)

	if err != nil {
		printAndExit("Error in crypto rand IV generation! " + err.Error())
	}
	encryptBlock := cipher.NewCBCEncrypter(ciphBlock, iv)

	encryptBlock.CryptBlocks(encrypt[aes.BlockSize:], plaintext)

	return encrypt
}

// returns an unencrypted slice of bytes
func decrypt(encrypted []byte, ciphBlock cipher.Block) []byte {
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	decryptBlock := cipher.NewCBCDecrypter(ciphBlock, iv)

	decrypt := make([]byte, len(encrypted))

	decryptBlock.CryptBlocks(decrypt, encrypted)

	return decrypt
}
