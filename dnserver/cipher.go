package toydns

import (
	"bytes"
	"crypto/aes"
	_cipher "crypto/cipher"
	"crypto/rand"
)

type dnsCipher struct {
	block _cipher.Block
}

const cipherBlockSize = 16

func newCipher(key []byte) (*dnsCipher, error) {
	key = PKCS5Padding(key, cipherBlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &dnsCipher{block: block}, nil
}

func (s *dnsCipher) encrypt(msg []byte) []byte {
	pmsg := PKCS5Padding(msg, cipherBlockSize)
	buf := make([]byte, len(pmsg)+cipherBlockSize)

	iv := buf[:cipherBlockSize]
	rand.Read(iv)
	encrypter := _cipher.NewCBCEncrypter(s.block, iv)
	encrypter.CryptBlocks(buf[cipherBlockSize:], pmsg)

	return buf
}

func (s *dnsCipher) decrypt(ctext []byte) []byte {
	return s._decrypt(ctext[:cipherBlockSize], ctext[cipherBlockSize:])
}

func (s *dnsCipher) _decrypt(iv []byte, ctext []byte) []byte {
	defer func() {
		if err := recover(); err != nil {
			logger.Error("%v", err)
		}
	}()
	decrypter := _cipher.NewCBCDecrypter(s.block, iv)
	buf := make([]byte, len(ctext))
	decrypter.CryptBlocks(buf, ctext)
	msg := PKCS5UnPadding(buf)

	return msg
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
