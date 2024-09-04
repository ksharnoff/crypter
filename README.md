# crypter
Creates an encrypted copy of a file. 

## what is this? 
With simple interactions in the terminal, any file can be copied and encrypted. 
Look in the examples folder to see test.pdf turn into a gibberish text file and then back into the original test.pdf. 

## encryption
The password is made into a key with Argon2. The bytes of the file input are read, encrypted with AES-256, and written to a new file. 

There are no checks if the user put in the correct password to decrypt, if the wrong password is put in, the resulting file will be nonsense. 

## salt or no salt?
There are two files that both encrypt files, `crypter.go` and `crypterDiffSalt.go`. 

`crypter.go` uses the same salt everytime in the AES encryption. Theoretically, a single salt for all encryption has the downside that when re-encrypting the same file, a malicious actor can see where the changes occurred. However, in this block cipher uses a cryptographically random list of bytes as well. So, everytime you encrypt the same file with the same password, it outputs different results.

`crypterDiffSalt.go` uses a different salt everytime in the AES encryption. Theoretically, a different salt for all encryption is the best practice, as the same file can be encrypted several times with the same password and it’ll look different. However, because of the random list of bytes mentioned above, there is no benefit to using `crypterDiffSalt.go`. 

`crypterDiffSalt.go` is more complex than `crypter.go`, splitting the first bit of the file into the salt and the second into the encrypted contents. If you would like a more complex file that is not more securely encrypted, use `crypterDiffSalt.go`, elsewise use `crypter.go`. 

## what’s the naming scheme?
Any new files created and encrypted will begin with `e-[file name].txt`. If it’s decrypted, it will be `d-[file name]`. So if you successfully decrypt a file that was encrypted by this program, it will make `d-e-[file name]`. If there is another file with the same name, `e-[file name].txt`, it will use two random digits to make `38e-[file name].txt`. 

## how do you use it?
Download either `crypter.go` or `crypterDiffSalt.go` after reading the above section. Download `go.mod` and `go.sum`. Make sure that the file you want to encrypt is in the same directory as the crypter.go file. 

Simply type `go run crypter.go` and answer the questions that appear.
![Example of encrypting a file. Done in terminal interactions. First the user gives the file name (here is test.pdf). Then the user chooses to encrypt or decrypt (here encrypt is chosen). Then the user gives their password. The password is deleted from the terminal. Then the success message is printed](https://github.com/ksharnoff/crypter/blob/main/examples/encryption_example.png)
