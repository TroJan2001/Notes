
here are many programs available for symmetric encryption. We will focus on two, which are widely used for asymmetric encryption as well:

- GNU Privacy Guard
- OpenSSL Project

### GNU Privacy Guard

The GNU Privacy Guard, also known as GnuPG or GPG, implements the OpenPGP standard.

We can encrypt a file using GnuPG (GPG) using the following command:

`gpg --symmetric --cipher-algo CIPHER message.txt`, where CIPHER is the name of the encryption algorithm. You can check supported ciphers using the command `gpg --version`. The encrypted file will be saved as `message.txt.gpg`.

The default output is in the binary OpenPGP format; however, if you prefer to create an ASCII armoured output, which can be opened in any text editor, you should add the option `--armor`. For example, `gpg --armor --symmetric --cipher-algo CIPHER message.txt`.

You can decrypt using the following command:

`gpg --output original_message.txt --decrypt message.gpg`

### OpenSSL Project

The OpenSSL Project maintains the OpenSSL software.

We can encrypt a file using OpenSSL using the following command:

`openssl aes-256-cbc -e -in message.txt -out encrypted_message`

We can decrypt the resulting file using the following command:

`openssl aes-256-cbc -d -in encrypted_message -out original_message.txt`

To make the encryption more secure and resilient against brute-force attacks, we can add `-pbkdf2` to use the Password-Based Key Derivation Function 2 (PBKDF2); moreover, we can specify the number of iterations on the password to derive the encryption key using `-iter NUMBER`. To iterate 10,000 times, the previous command would become:

`openssl aes-256-cbc -pbkdf2 -iter 10000 -e -in message.txt -out encrypted_message`

Consequently, the decryption command becomes:

`openssl aes-256-cbc -pbkdf2 -iter 10000 -d -in encrypted_message -out original_message.txt`