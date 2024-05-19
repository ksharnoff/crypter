package main

import (  
	// for main
	"fmt"
	"os"
	"strings"
	"time"
	"errors"
	"strconv"
	mathRand "math/rand"

	// for encrypting things
	"golang.org/x/crypto/argon2"
	"crypto/aes"
	"crypto/cipher"

 	// for iv generation
 	"io"
 	cryptRand "crypto/rand"
)

func main(){
	fmt.Print("-----------\nhello! these will be the steps:\n\tYou'll give the file name\n\tYou'll chose to encrypt or decrypt\n\tYou'll give your password\nA new file will have been made! wooo!\nTYPE 0 FOR HELP. TYPE ANSWER THEN return\n-----------\n")
	skipLine()

	var fileName string
	fmt.Print("What is the name of the file?: ")
	fmt.Scan(&fileName)

	for fileName == "0"{
	 	skipLine()
		fmt.Print("Make sure the file is in the same folder as this program!\nJust write exactly what the file is named\nAsk if you have more questions about this")
		skipLine()
		fmt.Print("What is the name of the file?: ")
		fmt.Scan(&fileName)
	}
	if doesFileExist(fileName){
		fmt.Println("Woo that file exists!")
	} else {
		fmt.Println("wopp wopp that file does not exist")
		os.Exit(1)
	}
	// from this point on, the file chosen does exist

	action := 0
	for (action != 1)&&(action != 2){
		skipLine()
		fmt.Print("Decyrypt (1) or encrypt (2)?: ")
		fmt.Scan(&action)
		if action == 0{
			skipLine()
			fmt.Print("Decrypt means to decode, make it a readable file.\nEncrypt does the opposite, hides it.\nAsk for further questions")
		}
	}

	fmt.Print("After you press return on your password, it will disappear!")
	password := "0"
	for password == "0"{
		skipLine()
		fmt.Println("What is your password?: ")
		fmt.Scan(&password)
		fmt.Print("\033[F\r", strings.Repeat(" ", len(password))) // deletes the password so its not in the terminal anymore
		if password == "0"{
			skipLine()
			if action == 1{
				fmt.Print("This is the password that you used to encrypt this file previously.\nIf you do not know it, idk")
			} else{
				fmt.Print("This will be the password you must remember to get this file back.\n Maybe write it down somewhere?")
			}
		}
		if len(password) < 5{
			fmt.Print("That password is too short, please use at least five characters!")
			password = "0"
		}
	}

	fmt.Println("THINGS ARE HAPPENING - DO NOT QUIT THE PROGRAM")

	ciphBlock, keyErr := keyGeneration(password)

	if keyErr != ""{
		fmt.Print("errror: " + keyErr)
		os.Exit(1)
	}

	input, inputErr := os.ReadFile(fileName) // input is an [] of bytes

	if inputErr != nil{ // if error in reading from file, ex: file doesn't exist
		fmt.Print("error in os.ReadFile " + inputErr.Error())
		os.Exit(1)
	}

	if len(input) == 0{
		fmt.Println("That file is empty!")
		os.Exit(0)
	}

	var outputToWrite []byte
	var newFileName string
	if action == 1{ // should be decrypted
		outputToWrite = decrypt(input, ciphBlock)
		newFileName = "d-"
	} else if action == 2{ // should encrypt
		outputToWrite = encrypt(input, ciphBlock)
		newFileName = "e-"
	} else{ // should never be this!
		fmt.Println("Problem! Didn't chose decrypt/encrypt!?")
		os.Exit(1)
	}


	fileNameLen := len(fileName)

	// delete the .txt or .yaml from the filename 
	if fileName[fileNameLen-4:] == ".txt" {
		fileName = fileName[:fileNameLen-4]
	} else if fileName[fileNameLen-5:] == ".yaml" {
		fileName = fileName[:fileNameLen-5]
	}

	// make unique file name for new file!
	newFileName += fileName + "-"

	currTime := time.Now()
	year, month, day := currTime.Date()

	newFileName += strconv.Itoa(year) + "." + strconv.Itoa(int(month)) + "." + strconv.Itoa(day) 
	
	// remember! a while loop in go is for
	for (doesFileExist(newFileName))||(doesFileExist(newFileName + ".txt")){ // hopefully shouldn't need to repeat
		newFileName += "-" + strconv.Itoa(randNum())
	}

	newFileName += ".txt"

	writeErr := os.WriteFile(newFileName + ".tmp", outputToWrite, 0600) // copied from pass: 0600 is  permissions that only this user can read/write/excet to this file

	if writeErr != nil{
		fmt.Println("Error in os.WriteFile " + writeErr.Error())
	}

	os.Rename(newFileName + ".tmp", newFileName) // only will do this if previous writing worked


	fmt.Println("All is done!")
	if action == 1{ // if decrypted
		fmt.Println("Btw, if you got the password wrong, the file will be gibberish!")
	}
}

func skipLine(){
	fmt.Print("\n")
}

// returns bool for if a file exists (within the
// directory / folder that this program is being run)
func doesFileExist(fileName string) bool{
	_, err := os.Stat(fileName) // os.Stat is a function to get info about file, and can return error
	if errors.Is(err, os.ErrNotExist){ // if the error is that the file doesn't exist
		return false
	}
	return true
}

func randNum() int{
	mathRand.Seed(time.Now().UnixNano()^int64(os.Getpid()))
	return mathRand.Intn(500) // should return number less than 500
}

// Makes a key, then a cipher block. returns "" if the 
// password generation was successfull. 
func keyGeneration(password string) (cipher.Block, string){
	if len([]byte(password)) < 1{
		return nil, "password for key generation is too short, string empty"
	}

	// Salt generation is going to be the same thing every time. 
	salt := []byte("zxcvbnmlkjhgfdsa")

	// func IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) 
	key := argon2.IDKey([]byte(password), salt, 2, 64*1024, 4, 32)

	ciphBlock, err := aes.NewCipher(key)

	if err != nil{
		return nil, err.Error()
	}
	return ciphBlock, ""
}

func encrypt(plaintext []byte, ciphBlock cipher.Block) []byte{
	// adds padding in form of "\n"
	if len(plaintext)%aes.BlockSize != 0{
		for i := len(plaintext)%aes.BlockSize; i < aes.BlockSize; i++{
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

func decrypt(encrypted []byte, ciphBlock cipher.Block) []byte{
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	decryptBlock := cipher.NewCBCDecrypter(ciphBlock, iv)

	decrypt := make([]byte, len(encrypted))

	decryptBlock.CryptBlocks(decrypt, encrypted)
	
	return decrypt
}