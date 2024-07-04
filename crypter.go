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
	fmt.Print("-----------\nHello! These will be the steps:\n\tYou'll give the file name\n\tYou'll chose to encrypt or decrypt\n\tYou'll give your password\nA new file will have been made! Wooo!\nType 0 for help.\nType your answer, then hit enter\n-----------\n")
	skipLine()

	var fileName string
	fmt.Print("What is the name of the file?: ")
	fmt.Scan(&fileName)

	for fileName == "0" {
		skipLine()
		fmt.Println("Make sure the file is in the same folder as this program!\nJust write exactly what the file is named\nMake sure that you include the extension!\n\taka 'testing.pdf' not just 'testing'")
		skipLine()
		fmt.Print("What is the name of the file?: ")
		fmt.Scan(&fileName)
	}
	if doesFileExist(fileName) {
		fmt.Println("Woo that file exists!")
	} else {
		fmt.Println("Wopp wopp that file does not exist")
		os.Exit(1)
	}
	// from this point on, the file chosen does exist

	action := 0
	for (action != 1) && (action != 2) {
		skipLine()
		fmt.Print("Decyrypt (1) or encrypt (2)?: ")
		fmt.Scan(&action)
		if action == 0 {
			skipLine()
			fmt.Print("Decrypt means to decode, make it a readable file.\nEncrypt does the opposite, it scrambles it.")
		}
	}

	fmt.Print("After you press return on your password, it will disappear!")
	password := "0"
	for password == "0" {
		skipLine()
		fmt.Println("What is your password?: ")
		fmt.Scan(&password)
		fmt.Print("\033[F\r", strings.Repeat(" ", len(password))) // deletes the password so its not in the terminal anymore
		if password == "0" {
			skipLine()
			if action == 1 {
				fmt.Print("This is the password that you used to encrypt this file previously.\nIf you do not know it, the file cannot be decrypted.")
			} else {
				fmt.Print("This will be the password you must remember to get this file back.\nMaybe write it down somewhere?")
			}
		}
		if len(password) < 6 {
			fmt.Print("That password is too short, please use at least six characters!")
			password = "0"
		}
	}

	fmt.Println("THINGS ARE HAPPENING - DO NOT QUIT THE PROGRAM")

	input, inputErr := os.ReadFile(fileName) // input is an [] of bytes

	if inputErr != nil { // if error in reading from file, ex: file doesn't exist
		fmt.Print("Error in os.ReadFile " + inputErr.Error())
		os.Exit(1)
	}

	if len(input) == 0 {
		fmt.Println("That file is empty! Error!!")
		os.Exit(0)
	}

	// to add -- salt generation at this point

	ciphBlock, keyErr := keyGeneration(password)

	if keyErr != "" {
		fmt.Print("Errror in key generation " + keyErr)
		os.Exit(1)
	}

	// assuming fileName input was testingtest.pdf
	// new encrypted file should be: e-testingtest.pdf.txt
	// or if decrypted: d-e-testingtest.pdf

	var outputToWrite []byte
	var newFileName string

	// decrypts or encrypts
	if action == 1 { // should decrypt
		outputToWrite = decrypt(input, ciphBlock)
		newFileName = "d"
	} else if action == 2 { // should encrypt
		outputToWrite = encrypt(input, ciphBlock)
		newFileName = "e"
	} else { // should never be this!
		fmt.Println("Problem! Didn't chose decrypt/encrypt!!")
		os.Exit(1)
	}

	newFileName += "-" + fileName

	// if the newFileName already exists then it adds a random two digits to the start
	// so it would look like: 38e-testingtest.pdf.txt
	for (doesFileExist(newFileName)) || (doesFileExist(newFileName + ".txt")) { // hopefully shouldn't need to repeat!
		newFileName = strconv.Itoa(randNum()) + newFileName // adds a random two digits to the start
	}

	if action == 1 { // if decrypting, remove the .txt added when encrypted, making the file go back to its original status of .pdf or etc
		beforeTxt, foundTxt := strings.CutSuffix(newFileName, ".txt")
		if foundTxt { // if newFileName did end in ".txt"
			newFileName = beforeTxt
		} else { // it shouldn't get to this else, if it was encrypted by crypter!
			_, foundYaml := strings.CutSuffix(newFileName, ".yaml") // if was encrypted by my pass manager will be testing.yaml, this will leave it as a .yaml

			if !foundYaml {
				fmt.Println("Are you sure that you want to Decrypt? Decyrypt (1) or encrypt (2)?: ")
				fmt.Scan(&action)

				if action == 1 {
					newFileName += ".txt"
					fmt.Println("THINGS ARE HAPPENING - DO NOT QUIT THE PROGRAM")
				} else {
					fmt.Println("Start over!")
					os.Exit(1)
				}
			}
		}
	} else { // if encrypting, add a .txt so it becomes a txt file
		newFileName += ".txt"
	}

	writeErr := os.WriteFile(newFileName+".tmp", outputToWrite, 0600) // 0600 is  permissions that only this user can read/write/excet to this file

	if writeErr != nil {
		fmt.Println("Error in os.WriteFile " + writeErr.Error())
	}

	os.Rename(newFileName+".tmp", newFileName) // only will do this if previous writing worked

	fmt.Println("All is done!")
	if action == 1 { // if decrypting
		fmt.Println("Btw, if you got the password wrong, the file will be gibberish!")
	}
}

func skipLine() {
	fmt.Print("\n")
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

func randNum() int {
	mathRand.Seed(time.Now().UnixNano() ^ int64(os.Getpid()))
	return mathRand.Intn(99) // should return number less than 99
}

// Makes a key, then a cipher block. returns "" if the
// password generation was successfull.
func keyGeneration(password string) (cipher.Block, string) {
	if len([]byte(password)) < 1 {
		return nil, "password for key generation is too short, string empty"
	}

	// Salt generation is going to be the same thing every time. TO DO - CHANGE
	salt := []byte("zxcvbnmlkjhgfdsa")

	// pass params: 4, 2048*1024, 4, 32 -- takes about 2 seconds
	// func IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32)
	// crypter params: 2, 64*1024, 4, 32
	key := argon2.IDKey([]byte(password), salt, 2, 64*1024, 4, 32)

	ciphBlock, err := aes.NewCipher(key)

	if err != nil {
		return nil, err.Error()
	}
	return ciphBlock, ""
}

func encrypt(plaintext []byte, ciphBlock cipher.Block) []byte {
	// adds padding in form of "\n"
	if len(plaintext)%aes.BlockSize != 0 {
		for i := len(plaintext) % aes.BlockSize; i < aes.BlockSize; i++ {
			plaintext = append(plaintext, 0x0A) // 0x0A = []byte("\n")
		}
	}
	encrypt := make([]byte, aes.BlockSize+len(plaintext))

	iv := encrypt[:aes.BlockSize]

	if _, err := io.ReadFull(cryptRand.Reader, iv); err != nil {
		panic(err)
	}
	encryptBlock := cipher.NewCBCEncrypter(ciphBlock, iv)

	encryptBlock.CryptBlocks(encrypt[aes.BlockSize:], plaintext)

	return encrypt
}

func decrypt(encrypted []byte, ciphBlock cipher.Block) []byte {
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	decryptBlock := cipher.NewCBCDecrypter(ciphBlock, iv)

	decrypt := make([]byte, len(encrypted))

	decryptBlock.CryptBlocks(decrypt, encrypted)

	return decrypt
}
