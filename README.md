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

cipher, _ := ffx.Encrypt(plainString)

plain, _ := ffx.Decrypt(cipher)
	
```
-----
##### WARNING: You probably shouldn't use this in a production environment. This lib was created primarily as yak-shaving for a research project. 
