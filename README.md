# Vault

This is a program which provides functionality for protecting files through
symmetric key encryption.
In particular, a user can create a password protected vault and store encrypted
versions of files in the vault.
When need be, the user can then retrieve these files from the vault.

## Usage

Say a vault called `secrets` is created using the following invocations of the
`vault` binary.
```bash
# all of the following are equivalent invocations
./vault --create secrets
./vault --create=secrets
./vault -create=secrets
./vault -create secrets
```
The program will prompt the user for a password and upon success, a directory
called `vault` will appear in the current working directory.
A single file, called `vault.bin` is in that directory and it contains
information such as the file entries for files being managed by the vault.

__Note__: The user is advised to avoid any corruption to the `vault.bin` file.
In such a case, it may be impossible to decrypt the encrypted files being stored
in the vault.

__Note__: In the following, _plaintext_ (file) refers to an unencrypted file,
whereas _ciphertext_ (file) refers to an encrypted file.

__Encrypting a file__:
To encrypt and store a file, say `secrets.txt`, in the `secrets` vault, the
following command is used.
```bash
./vault --vault=secrets --encrypt secrets.txt
```
The `--vault=secrets` specifies which vault is being operated on.
Then `--encrypt secrets.txt` commands the program to encrypt the file called
`secrets.txt` and add its corresponding file entry in the vault.
Whenever a command (such as this one) operating on a vault is executed, the user
is asked for the vault's password (which was set when the vault was created).

If no errors occur, there should be another file in the `secrets` directory
containing the ciphertext corresponding to the `secrets.txt` plaintext file.
The name of this file will be different from `secrets.txt` and the file itself
will contain the encrypted version of `secrets.txt`.

__Decrypting a file__:
To decrypt a file, say `secrets.txt`, which is in the vault `secrets`, the
following command is used.
```bash
./vault --vault=secrets --decrypt secrets.txt --output decrypted_secrets.txt
```
This command searches for a file entry corresponding to `secrets.txt` in the
`secrets` vault and decrypts the ciphertext version to a plaintext file called
`decrypted_secrets.txt`.
If the `--output` flag is omitted, then the plaintext file will bear the
original name, `secrets.txt`.

__Note__: When decrypting, the output plaintext file will be truncated!

__Removing a file__:
To remove a file, say `secrets.txt`, from the `secrets` vault, the following
command is used.
```bash
./vault --vault=secrets --remove secrets.txt
```
This removes the file entry corresponding to `secrets.txt` from the `vault.bin`
file and deletes the ciphertext file corresponding to it.

## Technical Details

### Encryption

The encryption standard used is AES, with 128, 192 and 256 bit key-size
variants.
Each file in the vault has an associated `VaultEntry` and each file is encrypted
using a different initializing vector (IV).
The initializing vector, padding length, original filename and other key
information needed for decrypting the file is stored in the entry.

The file entries are stored in the vault's `vault.bin` file.
This is why it is essential that `vault.bin` is protected from corruption.
If possible, the user should store a backup of this file in order to be able to
access the vault's contents even after the original `vault.bin` file has been
corrupted.

### Authentication

The HMAC tag of a file's ciphertext is stored in its file entry.
This tag is then used to verify that the ciphertext has not been tampered with
and therefore ensures data integrity.
