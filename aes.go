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
	salt []byte
}

func NewCipher(salt string) Encryptor {
	return &encryptor{salt: []byte(salt)}
}

func (e *encryptor) EncryptBytes(input []byte, password string) ([]byte, error) {
	bit16Salt := [16]byte{}
	for i := 0; i < 15; i++ {
		bit16Salt = md5.Sum(e.salt)
		bit16Salt = md5.Sum(bit16Salt[:])
	}
	passwordBytes := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(passwordBytes[:])
	if err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, bit16Salt[:])
	cipherText := make([]byte, len(input))
	cfb.XORKeyStream(cipherText, input)
	return cipherText, nil
}

func (e *encryptor) DecryptBytes(input []byte, password string) ([]byte, error) {
	bit16Salt := [16]byte{}
	for i := 0; i < 15; i++ {
		bit16Salt = md5.Sum(e.salt)
		bit16Salt = md5.Sum(bit16Salt[:])
	}
	passwordBytes := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(passwordBytes[:])
	if err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBDecrypter(block, bit16Salt[:])
	plainText := make([]byte, len(input))
	cfb.XORKeyStream(plainText, input)
	return plainText, nil
}

func (e *encryptor) Encrypt(text, password string) (string, error) {
	bit16Salt := md5.Sum(e.salt) //nolint:gosec
	passwordBytes := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(passwordBytes[:])
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bit16Salt[:])
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return encode(cipherText), nil
}

func (e *encryptor) Decrypt(text, password string) (string, error) {
	bit16Salt := md5.Sum(e.salt) //nolint:gosec
	passwordBytes := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(passwordBytes[:])
	if err != nil {
		return "", err
	}
	cipherText := decode(text)
	cfb := cipher.NewCFBDecrypter(block, bit16Salt[:])
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
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
