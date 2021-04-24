package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func (v *AESVault) newEncryptor(iv []byte) (cipher.BlockMode, []byte, error) {
	// initialize the cipher
	c, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, nil, err
	}
	if iv == nil {
		iv = make([]byte, c.BlockSize())
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, nil, fmt.Errorf("failed to initialize IV: %s", err.Error())
		}
	} else {
		iv = iv[:c.BlockSize()]
	}
	encryptor := cipher.NewCBCEncrypter(c, iv)
	return encryptor, iv, nil
}

func (v *AESVault) newDecryptor(iv []byte) (cipher.BlockMode, error) {
	// initialize the cipher
	c, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}
	if iv == nil {
		iv = make([]byte, c.BlockSize())
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, fmt.Errorf("failed to initialize IV: %s", err.Error())
		}
	}
	encryptor := cipher.NewCBCDecrypter(c, iv[:c.BlockSize()])
	return encryptor, nil
}
