package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

func (v *AESVault) encrypt(src, dst *os.File) (*AESVaultEntry, error) {
	// stat the source file
	stat, err := src.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat src file: %s", err.Error())
	}
	// prepare the encryptor
	enc, iv, err := v.newEncryptor(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cipher: %s", err.Error())
	}
	// if required, determine the file padding
	var paddingLen int64
	if stat.Size()%int64(enc.BlockSize()) != 0 {
		paddingLen = int64(enc.BlockSize()) - stat.Size()%int64(enc.BlockSize())
	}
	// prepare the file entry for the vault
	fileEntry := &AESVaultEntry{
		Filename:      stat.Name(),
		Size:          stat.Size(),
		IV:            iv,
		EncryptedName: dst.Name(),
		Padding:       paddingLen,
	}
	// write the encrypted version of the file to disk (dst)
	srcBuff := make([]byte, enc.BlockSize())
	dstBuff := make([]byte, enc.BlockSize())

	// determine the number of blocks in the src file
	blockCount := stat.Size() / int64(enc.BlockSize())
	if paddingLen != 0 {
		blockCount++
	}
	// initialize HMAC
	mac := hmac.New(sha256.New, v.key)
	// encrypt block by block
	for i := int64(0); i < blockCount; i++ {
		// read the file on disk into the src buffer
		if n, err := io.ReadFull(src, srcBuff); err != nil {
			// not all bytes were read
			if i != blockCount-1 {
				return nil, fmt.Errorf("file read error: %s", err.Error())
			}
			if n != enc.BlockSize() {
				// pad the buffer
				copy(srcBuff[n:], make([]byte, enc.BlockSize()-n))
			}
		}
		// crypt the src buffer into the dst buffer
		enc.CryptBlocks(dstBuff, srcBuff)
		mac.Write(dstBuff) // write ciphertext to hmac
		// write the dst buffer to dst file on disk
		dst.WriteAt(dstBuff, i*int64(enc.BlockSize()))
	}
	// store the HMAC in the file entry
	fileEntry.HMAC = mac.Sum(nil)
	return fileEntry, nil
}

func (v *AESVault) decrypt(srcEntry *AESVaultEntry, src, dst *os.File) error {
	// stat the src file to get size and determine number of ciphertext blocks
	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat encryted file: %s", err.Error())
	}
	// decrypt blocks
	dec, err := v.newDecryptor(srcEntry.IV)
	if err != nil {
		return fmt.Errorf("failed to initialize decryptor: %s", err.Error())
	}
	numBlocks := info.Size() / int64(dec.BlockSize())
	srcBuff := make([]byte, dec.BlockSize())
	dstBuff := make([]byte, dec.BlockSize())
	// initialize HMAC
	mac := hmac.New(sha256.New, v.key)
	for i := int64(0); i < numBlocks; i++ {
		// read data into the src buffer from the src file
		if _, err := io.ReadFull(src, srcBuff); err != nil {
			return fmt.Errorf("src file read error: %s", err.Error())
		}
		mac.Write(srcBuff) // write ciphertext to hmac
		// decrypt the src buffer into the dst buffer
		dec.CryptBlocks(dstBuff, srcBuff)
		// remove padding from last block, if any
		if i == numBlocks-1 && srcEntry.Padding != 0 {
			dstBuff = dstBuff[:(dec.BlockSize() - int(srcEntry.Padding))]
		}
		// write dst buff to file
		dst.WriteAt(dstBuff, i*int64(dec.BlockSize()))
	}
	// verify that the ciphertext hmac is the same as the one in the srcR
	hmacTag := mac.Sum(nil)
	if !hmac.Equal(hmacTag, srcEntry.HMAC) {
		return fmt.Errorf("ciphertext auth fail - possibility of tampering")
	}
	return nil
}
