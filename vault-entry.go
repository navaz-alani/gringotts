package main

type VaultEntry interface {
	// original name of the file
	Name() string
	// size of the file
	FileSize() int64
}

type AESVaultEntry struct {
	Filename      string
	EncryptedName string
	IV            []byte
	Size          int64
	Padding       int64
}

func (e *AESVaultEntry) Name() string    { return e.Filename }
func (e *AESVaultEntry) FileSize() int64 { return e.Size }
