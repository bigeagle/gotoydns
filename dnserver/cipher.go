package toydns

import (
	"bytes"
	"crypto/aes"
	_cipher "crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
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
	buf := make([]byte, len(pmsg)+cipherBlockSize+4)

	iv := buf[:cipherBlockSize]
	rand.Read(iv)
	encrypter := _cipher.NewCBCEncrypter(s.block, iv)
	encrypter.CryptBlocks(buf[cipherBlockSize:len(buf)-4], pmsg)
	crc := crc32.ChecksumIEEE(pmsg)
	binary.BigEndian.PutUint32(buf[len(buf)-4:], crc)

	return buf
}

func (s *dnsCipher) decrypt(ctext []byte) []byte {
	if len(ctext) < (cipherBlockSize<<1)+4 {
		return []byte{}
	}

	iv := ctext[:cipherBlockSize]
	cmsg := ctext[cipherBlockSize : len(ctext)-4]
	crc := ctext[len(ctext)-4:]

	pmsg := s._decrypt(iv, cmsg)

	if binary.BigEndian.Uint32(crc) != crc32.ChecksumIEEE(pmsg) {
		return []byte{}
	}
	return pmsg
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
