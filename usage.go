package main

import "fmt"

const usageMsg string = `vault is a virtual store for encrypted files.
It provides functionality for creating and managing a vault (adding, removing,
decrypting files).

USE CASES:
When storing sensitive information (such as identification documents, legal
documents etc.) on a flash drive/hard disk.
If the remote storage device is lost/stolen/accessed by unauthorized parties,
then some level of confidentiality is provided.

WARNING:
This is a symmetric-key encryption system so the user is advised to manage the
encryption key carefully and prevent its compromise.
This includes selecting a strong key, storing the key in a safe & secure place
(such as remembering it and not writing it down/saving it on a file) and
sharing it with other parties through a secure channel (such as in-person or
over a secure end-to-end encrypted communication system).

Usage: vault --<command> [argument]

Available commands are documented below, in order of decreasing precedence.
This means that if both "--create <some vault>" and "--add <some file>" are
specified, then ONLY the create command will be executed.

--help
  Display this help menu.

--create <vault name>
  Creates a new vault with the specified name.

--vault <vault name>
  This specifies the vault that is being operated on.
  It needs to be specified when using operational commands, which are shown
  below.

--list
  Lists the files in the vault.

--encrypt <filename>
  Encrypts and adds the specified file to the vault being operated on.

--decrypt <filename>
  If a file with the given name is stored in the vault, this decrypts the file
  and stores it in the current directory with its original name.

--remove <filename>
  Removes an encrypted file from the vault.
  Be careful when using this as the file, once deleted, is not recoverable.`

func usage() {
	fmt.Print(usageMsg)
}
