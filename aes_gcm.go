package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

//
func main() {
	key := []byte("abcd1efgh2ijk234lmnopq234rsrtyu7")
	plaintext := "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm"
	iv := []byte("fgrtyuio21FR") //make([]byte, 12)
	encrypted, _ := AESGCMEncrypter(plaintext, key, iv)
	// kj+cPeGVoNvI6v7iLEBbzKXotDT9AQV+XYcicvGMKSn7/yLfwZCouS4e1Cji3I9ZvMYvrPRSVxZq6sdV0IzJH5D2XloeWRajgPZ6uzOCgGbDdxEf7ywf63KYss2KQK6JrFhkG4zlbSY=
	fmt.Println("encrypted", encrypted)
	decrypted, _ := AESGCMDecrypter(encrypted, key, iv)
	// This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm
	fmt.Println("decrypted", string(decrypted))
}

// AES-GCM should be used because the operation is an authenticated encryption
// algorithm designed to provide both data authenticity (integrity) as well as
// confidentiality.

func AESGCMEncrypter(src string, key, iv []byte) (encrypted string, err error) {

	plaintext := []byte(src)

	block, errNewCipher := aes.NewCipher(key)
	if errNewCipher != nil {
		err = errNewCipher
		return
	}

	aesgcm, errNewGCM := cipher.NewGCM(block)
	if errNewGCM != nil {
		err = errNewGCM
		return
	}

	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)
	encrypted = base64.StdEncoding.EncodeToString(ciphertext)
	return
}

func AESGCMDecrypter(crypt string, key, iv []byte) (decrypted []byte, err error) {

	ciphertext, errBase64 := base64.StdEncoding.DecodeString(crypt)
	if errBase64 != nil {
		err = errBase64
		return
	}

	block, errNewCipher := aes.NewCipher(key)
	if errNewCipher != nil {
		err = errNewCipher
		return
	}

	aesgcm, errNewGCM := cipher.NewGCM(block)
	if errNewGCM != nil {
		err = errNewGCM
		return
	}

	decrypted, err = aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return
	}

	return decrypted, err
}
