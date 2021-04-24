package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

type encType uint8

// Supported encryption types - AES variants only
const (
	AES_256 encType = 0
	AES_192 encType = 1
	AES_128 encType = 2
)

// Vault defines the interface for interacting with an encrypted store of files.
type Vault interface {
	AddFile(name string) error
	RetrieveFile(name string) error
	FileList() []string
	ChangeEncryptionKey(key []byte) error
	Close() error
}

// AESVault is Vault implementation which secures its contents with AES
// encryption.
type AESVault struct {
	dirName    string
	Name       string
	Encryption encType
	key        []byte
	Files      []*AESVaultEntry
}

// NewAESVault creates a new AESValut as a file in the file system.
// `enc` specifies the AES variant to use and
// `key` is the encryption key to be used.
//
// Note that the key is not directly used to encrypt the files.
// Instead, the key is hashed and the resulting checksum bytes are used as key
// bytes for the chosen AES variant.
func NewAESVault(enc encType, name string, key []byte) (*AESVault, error) {
	err := os.Mkdir(name, os.ModeDir|0777)
	if os.IsExist(err) {
		return nil, fmt.Errorf("directory with vault name '%s' already exists", name)
	} else if err != nil {
		return nil, fmt.Errorf("error creating vault directory '%s': %s", name, err.Error())
	}
	v := &AESVault{
		dirName:    name,
		Encryption: enc,
		key:        processKey(enc, key),
	}
	return v, nil
}

func OpenAESVault(enc encType, name string, key []byte) (*AESVault, error) {
	v := new(AESVault)
	v.dirName = name
	v.key = processKey(enc, key)
	if err := v.decodeFromFile(name); err != nil {
		return nil, fmt.Errorf("vault decode error: %s", err.Error())
	}
	return v, nil
}

// processKey hashes the key and, based on the AES variant, returns the required
// number of bytes for the AES key.
func processKey(enc encType, key []byte) []byte {
	// Key sizes as specified by "crypto/aes":
	// The key argument should be the AES key, either 16, 24, or 32 bytes to
	// select AES-128, AES-192, or AES-256.
	keyHash := sha256.Sum256(key)
	return keyHash[:32-int(enc)*8]
}

func (v *AESVault) encryptedFileName(srcFile string) string {
	hash := sha256.Sum256([]byte(srcFile))
	return v.dirName + "/" + base64.StdEncoding.EncodeToString(hash[:])
}

func (v *AESVault) lookupFile(name string) (int, *AESVaultEntry) {
	for i, entry := range v.Files {
		if entry.Filename == name {
			return i, entry
		}
	}
	return -1, nil
}

func (v *AESVault) Close() error {
	// write the vault to disk
	return v.encodeToFile()
}

func (v *AESVault) ListFiles() []VaultEntry {
	var files []VaultEntry
	for _, e := range v.Files {
		files = append(files, e)
	}
	return files
}

func (v *AESVault) AddFile(name string) error {
	// open the src file
	src, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("error opening src file '%s': %s", name, err.Error())
	}
	defer src.Close()
	// open the dst file
	dst, err := os.OpenFile(v.encryptedFileName(name), os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("error creating dst file: %s", err.Error())
	}
	defer dst.Close()
	// encrypt and add src file to the vault
	if entry, err := v.encrypt(src, dst); err != nil {
		return fmt.Errorf("encryption error: %s", err.Error())
	} else {
		v.Files = append(v.Files, entry)
	}
	return nil
}

func (v *AESVault) RetrieveFile(name, output string) error {
	// retrieve the entry (if any) corresponding to the specified file
	_, entry := v.lookupFile(name)
	if entry == nil {
		return fmt.Errorf("no entry for '%s' in vault", name)
	}
	// open the encrypted file
	src, err := os.Open(entry.EncryptedName)
	if err != nil {
		return fmt.Errorf("error opening encryted file: %s", err.Error())
	}
	// open a file to save decrypted output
	if output == "" {
		output = entry.Filename
	}
	dst, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("error creating output file: %s", err.Error())
	}

	if err := v.decrypt(entry, src, dst); err != nil {
		return err
	}
	return nil
}

func (v *AESVault) RemoveFile(name string) error {
	idx, entry := v.lookupFile(name)
	if entry == nil {
		return fmt.Errorf("no entry for '%s' in vault", name)
	}
	if err := os.Remove(entry.EncryptedName); err != nil {
		return fmt.Errorf("failed to delete encrypted file: %s", err.Error())
	}
	// remove entry from vault
	v.Files[idx] = v.Files[len(v.Files)-1]
	v.Files = v.Files[:len(v.Files)-1]
	return nil
}
