# perm-crypt
A Golang implementation of the AES-FFX Format-Preserving Encryption Scheme 

# Installation 
```bash
$ go get github.com/roasbeef/perm-crypt
```

# Example Usage
```go
key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")

tweak := []byte("9876543210")

plainString := "0123456789"

ffx, _ := aesffx.NewCipher(10, key, tweak)

cipher, err := aes.Encrypt(plainString)

plain, _ := aes.Decrypt(cipher)
	
```
