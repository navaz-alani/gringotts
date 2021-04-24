package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	help    *bool   = flag.Bool("help", false, "display help menu")
	create  *string = flag.String("create", "", "name of the vault to create")
	vault   *string = flag.String("vault", "", "name of the vault to operate on")
	list    *bool   = flag.Bool("list", false, "display list of files in the vault")
	encrypt *string = flag.String("encrypt", "", "name of file to encrypt & add to the vault")
	decrypt *string = flag.String("decrypt", "", "name of file to decrypt from the vault")
	output  *string = flag.String("output", "", "name of file to save decrypted file as")
	remove  *string = flag.String("remove", "", "name of file to delete from the vault")
)

func exitOnErr(ctxStr string, err error, code int) {
	if err != nil {
		fmt.Printf("%s: %s\n", ctxStr, err.Error())
	} else {
		fmt.Printf("%s\n", ctxStr)
	}
	os.Exit(code)
}

func main() {
	flag.Parse()
	if *help {
		usage()
		os.Exit(0)
	}
	// create a new vault
	if *create != "" {
		vaultName := *create
		pwd, err := getPassword(fmt.Sprintf("Enter a password for '%s': ", vaultName))
		if err != nil {
			exitOnErr("error reading password", err, 1)
		}
		if v, err := NewAESVault(AES_256, vaultName, pwd); err != nil {
			exitOnErr("error creating vault", err, 1)
		} else {
			if err := v.Close(); err != nil {
				exitOnErr("error closing vault", err, 1)
			}
		}
		return
	}
	// open vault
	var v *AESVault
	var pwd []byte
	var err error
	// from here on, we are working with an existing vault
	if *vault == "" {
		exitOnErr("expected a vault to operate on, use flag --help", nil, 1)
	}
	pwd, err = getPassword(fmt.Sprintf("Enter password for '%s': ", *vault))
	if err != nil {
		exitOnErr("error reading password", err, 1)
	}
	v, err = OpenAESVault(AES_256, *vault, pwd)
	if err != nil {
		exitOnErr(fmt.Sprintf("error opening '%s'", *vault), err, 1)
	}
	// ensure that the vault is closed and thus all changes are saved
	defer func() {
		if err := v.Close(); err != nil {
			exitOnErr("vault save error", err, 1)
		}
	}()

	// now we can operate on the open vault

	// command = list files in vault
	if *list {
		for _, entry := range v.ListFiles() {
			fmt.Printf("%s %db\n", entry.Name(), entry.FileSize())
		}
		return
	}
	// command = encrypt a file
	if *encrypt != "" {
		if err := v.AddFile(*encrypt); err != nil {
			exitOnErr("encrypt error", err, 1)
		}
		return
	}
	// command = decrypt a file
	if *decrypt != "" {
		if err := v.RetrieveFile(*decrypt, *output); err != nil {
			exitOnErr("decrypt error", err, 1)
		}
		return
	}
	// command = remove a file
	if *remove != "" {
		if err := v.RemoveFile(*remove); err != nil {
			exitOnErr("remove error", err, 1)
		}
		return
	}

  exitOnErr("expected command, use flag --help", nil, 1)
}
