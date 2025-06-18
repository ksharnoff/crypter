# crypter
Creates an encrypted copy of a file. 

## what is this? 
With simple interactions in the terminal, any file can be copied and encrypted. 
Look in the examples folder to see `test.pdf` turn into an encrypted (gibberish-looking) text file and then back into the original `test.pdf`. 

## encryption
The password is made into a key with Argon2. The bytes of the file input are read, encrypted with AES-256, and written to a new file. The password used to encrypt is never saved or written to a file. 

There are no checks if the user put in the correct password to decrypt - if the wrong password is put in, the resulting file will be nonsense. 

## should there be a different salt?
`crypter.go` uses the same salt every time in its AES encryption. Theoretically, a single salt for all encryption has the downside that when re-encrypting the same file, a malicious actor can see where the changes occurred. However, this block cipher (from Argon2) uses a cryptographically random list of bytes. So, every time you encrypt the same file with the same password, it outputs different results.

## what’s the naming scheme?
Any new files created and encrypted will begin with `e-[file name].txt`. If it's decrypted, it will be `d-[file name]`. So if you successfully decrypt a file that was encrypted by this program, it will make `d-e-[file name]`. If there is another file with the same name, `e-[file name].txt`, it will use two random digits to make `38e-[file name].txt`. 

## how do you use it?
Download `crypter.go`, `go.mod`, and `go.sum`. Make sure that the file you want to encrypt is in the same directory as the `crypter.go` file. 

Simply type `go run crypter.go` and answer the questions that appear.
![Example of encrypting a file. Done in terminal interactions. First the user gives the file name (here is test.pdf). Then the user chooses to encrypt or decrypt (here encrypt is chosen). Then the user gives their password. The password is deleted from the terminal. Then the success message is printed](https://github.com/ksharnoff/crypter/blob/main/examples/encryption_example.png)
