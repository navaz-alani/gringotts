package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"os"
)

const vaultFile string = "/vault.bin"

// vaultIV is a random 32 bit IV for the vault encoder/decoder
var vaultIV []byte = []byte{
	0x7f, 0x4a, 0xe2, 0x38, 0x31, 0xd5, 0x4c, 0x05,
	0xfe, 0x4c, 0x36, 0xb4, 0x83, 0x79, 0x51, 0xa8,
	0x51, 0xb7, 0xd1, 0xe1, 0x9e, 0x71, 0x3f, 0xfb,
	0xa1, 0xae, 0x35, 0xec, 0x50, 0x4e, 0x74, 0xdc,
}

// encodeToFile encodes the Vault structure to disk.
func (v *AESVault) encodeToFile() error {
	saveFileName := v.dirName + vaultFile
	f, err := os.OpenFile(saveFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return fmt.Errorf("error opening vault file: %s", err.Error())
	}
	// encode vault to binary in buff
	var buff bytes.Buffer
	if err := gob.NewEncoder(&buff).Encode(v); err != nil {
		return fmt.Errorf("error encoding vault: %s", err.Error())
	}
	buffLen := len(buff.Bytes())
	// encrypt the contents of buff
	enc, _, err := v.newEncryptor(vaultIV)
	if err != nil {
		return fmt.Errorf("error initializing encryptor: %s", err.Error())
	}
	numBlocks := buffLen / enc.BlockSize()
	overflow := buffLen % enc.BlockSize()
	if overflow != 0 {
		numBlocks += 1
		buff.Write(make([]byte, enc.BlockSize()-overflow))
	}
	for i := 0; i < numBlocks; i++ {
		lb := i * enc.BlockSize()
		ub := (i + 1) * enc.BlockSize()
		enc.CryptBlocks(buff.Bytes()[lb:ub], buff.Bytes()[lb:ub])
	}
	// write contents of the buffer to the save file
	if n, err := f.Write(buff.Bytes()); err != nil {
		return fmt.Errorf("error writing vault (%d bytes/%d bytes): %s", n, buffLen, err.Error())
	}
	return nil
}

// decodeFromFile decodes the Vault structure from the disk to an in-memory,
// workable representation.
func (v *AESVault) decodeFromFile(name string) error {
	saveFileName := name + vaultFile
	f, err := os.OpenFile(saveFileName, os.O_RDONLY, 0666)
	if err != nil {
		return fmt.Errorf("error opening vault file: %s", err.Error())
	}
	// read contents of file into buff
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("error reading vault file: %s", err.Error())
	}
	// decrypt the contents of the buffer
	dec, err := v.newDecryptor(vaultIV)
	if err != nil {
		return fmt.Errorf("error initializing deryptor: %s", err.Error())
	}
	numBlocks := len(data) / dec.BlockSize()
	paddingLen := len(data) % dec.BlockSize()
	if paddingLen != 0 {
		return fmt.Errorf("error decrypting vault: excess data in vault file")
	}
	buff := make([]byte, len(data))
	for i := 0; i < numBlocks; i++ {
		lb := i * dec.BlockSize()
		ub := (i + 1) * dec.BlockSize()
		dec.CryptBlocks(buff[lb:ub], data[lb:ub])
	}
	// decode the contents of the buffer into the vault
	if err := gob.NewDecoder(bytes.NewBuffer(buff)).Decode(v); err != nil {
		return fmt.Errorf("incorrect password/corrupted vault file")
	}
	return nil
}
