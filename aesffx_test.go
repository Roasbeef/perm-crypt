package aesffx

import (
	"encoding/hex"
	"testing"
)

// Test vectors taken from:
//  * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt

func TestVector1(t *testing.T) {
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	if err != nil {
		t.Fatalf("Unable to decode hex key: %v", key)
	}

	tweak := []byte("9876543210")
	plainString := "0123456789"

	aes, err := NewCipher(10, key, tweak)
	if err != nil {
		t.Fatalf("Unable to create cipher: %v", err)
	}

	cipher, err := aes.Encrypt(plainString)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if cipher != "6124200773" {
		t.Fatalf("Encryption was incorrect. Need %v, got %v",
			"6124200773", cipher)
	}

	plain, err := aes.Decrypt(cipher)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if plain != plainString {
		t.Fatalf("Decryption unsuccessful. Need %v, got %v",
			plainString, plain)
	}
}

func TestVector2(t *testing.T) {
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	if err != nil {
		t.Fatalf("Unable to decode hex key: %v", key)

	}

	var tweak []byte
	plainString := "0123456789"

	aes, err := NewCipher(10, key, tweak)
	if err != nil {
		t.Fatalf("Unable to create cipher: %v", err)
	}

	cipher, err := aes.Encrypt(plainString)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if cipher != "2433477484" {
		t.Fatalf("Encryption was incorrect. Need %v, got %v",
			"2433477484", cipher)
	}

	plain, err := aes.Decrypt(cipher)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if plain != plainString {
		t.Fatalf("Decryption unsuccessful. Need %v, got %v",
			plainString, plain)
	}
}

func TestVector3(t *testing.T) {
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	if err != nil {
		t.Fatalf("Unable to decode hex key: %v", key)

	}

	tweak := []byte("2718281828")
	plainString := "314159"

	aes, err := NewCipher(10, key, tweak)
	if err != nil {
		t.Fatalf("Unable to create cipher: %v", err)
	}

	cipher, err := aes.Encrypt(plainString)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if cipher != "535005" {
		t.Fatalf("Encryption was incorrect. Need %v, got %v",
			"535005", cipher)
	}

	plain, err := aes.Decrypt(cipher)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if plain != plainString {
		t.Fatalf("Decryption unsuccessful. Need %v, got %v",
			plainString, plain)
	}
}

func TestVector4(t *testing.T) {
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	if err != nil {
		t.Fatalf("Unable to decode hex key: %v", key)

	}
	tweak := []byte("7777777")
	plainString := "999999999"

	aes, err := NewCipher(10, key, tweak)
	if err != nil {
		t.Fatalf("Unable to create cipher: %v", err)
	}

	cipher, err := aes.Encrypt(plainString)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if cipher != "658229573" {
		t.Fatalf("Encryption was incorrect. Need %v, got %v",
			"658229573", cipher)
	}

	plain, err := aes.Decrypt(cipher)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if plain != plainString {
		t.Fatalf("Decryption unsuccessful. Need %v, got %v",
			plainString, plain)
	}
}
