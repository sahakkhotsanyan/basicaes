package basicaes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" //nolint:gosec
	"crypto/sha256"
	"encoding/base64"
)

type Encryptor interface {
	Encrypt(string, string) (string, error)
	Decrypt(string, string) (string, error)
	EncryptBytes([]byte, string) ([]byte, error)
	DecryptBytes([]byte, string) ([]byte, error)
}

type encryptor struct {
	salt   []byte
	rounds int
}

func NewCipher(salt string, rounds int) Encryptor {
	return &encryptor{salt: []byte(salt), rounds: rounds}
}

func (e *encryptor) EncryptBytes(input []byte, password string) ([]byte, error) {
	bit16Salt := [16]byte{}
	bit16Salt = md5.Sum(e.salt)
	for i := 0; i < e.rounds; i++ {
		bit16Salt = md5.Sum(bit16Salt[:])
	}
	passwordBytes := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(passwordBytes[:])
	if err != nil {
		return nil, err
	}

	cipherText := input
	for i := 0; i < e.rounds; i++ {
		cfb := cipher.NewCFBEncrypter(block, bit16Salt[:])
		tempCipherText := make([]byte, len(cipherText))
		cfb.XORKeyStream(tempCipherText, cipherText)
		cipherText = tempCipherText
	}
	return cipherText, nil
}

func (e *encryptor) DecryptBytes(input []byte, password string) ([]byte, error) {
	bit16Salt := [16]byte{}
	bit16Salt = md5.Sum(e.salt)
	for i := 0; i < e.rounds; i++ {
		bit16Salt = md5.Sum(bit16Salt[:])
	}
	passwordBytes := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(passwordBytes[:])
	if err != nil {
		return nil, err
	}

	plainText := input
	for i := 0; i < e.rounds; i++ {
		cfb := cipher.NewCFBDecrypter(block, bit16Salt[:])
		tempPlainText := make([]byte, len(plainText))
		cfb.XORKeyStream(tempPlainText, plainText)
		plainText = tempPlainText
	}
	return plainText, nil
}

func (e *encryptor) Encrypt(text, password string) (string, error) {
	bit16Salt := md5.Sum(e.salt) //nolint:gosec
	for i := 0; i < e.rounds; i++ {
		bit16Salt = md5.Sum(bit16Salt[:])
	}
	passwordBytes := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(passwordBytes[:])
	if err != nil {
		return "", err
	}

	plainText := []byte(text)
	cipherText := plainText
	for i := 0; i < e.rounds; i++ {
		cfb := cipher.NewCFBEncrypter(block, bit16Salt[:])
		tempCipherText := make([]byte, len(cipherText))
		cfb.XORKeyStream(tempCipherText, cipherText)
		cipherText = tempCipherText
	}
	return encode(cipherText), nil
}

func (e *encryptor) Decrypt(text, password string) (string, error) {
	bit16Salt := md5.Sum(e.salt) //nolint:gosec
	for i := 0; i < e.rounds; i++ {
		bit16Salt = md5.Sum(bit16Salt[:])
	}
	passwordBytes := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(passwordBytes[:])
	if err != nil {
		return "", err
	}

	cipherText := decode(text)
	plainText := cipherText
	for i := 0; i < e.rounds; i++ {
		cfb := cipher.NewCFBDecrypter(block, bit16Salt[:])
		tempPlainText := make([]byte, len(plainText))
		cfb.XORKeyStream(tempPlainText, plainText)
		plainText = tempPlainText
	}
	return string(plainText), nil
}

func encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
func decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}
