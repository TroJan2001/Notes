
GnuPG or GPG is an Open Source implementation of PGP from the GNU project. You may need to use GPG to decrypt files in CTFs. With PGP/GPG, private keys can be protected with passphrases in a similar way to SSH private keys. If the key is passphrase protected, you can attempt to crack this passphrase using John The Ripper and gpg2john.

# Useful Commands:

To generate a key pair:

```bash
gpg --gen-key
```

To encrypt your email using command line:

```bash
gpg --encrypt --sign --armor -r strategos@tryhackme.thm message.tx
```

Notice the following options:

1. `gpg`: This is the command to invoke GPG.
2. `--encrypt`: This option tells GPG to perform encryption.
3. `--sign`: This option tells GPG to sign the message. When you sign a message, you use your private key to create a digital signature that can be used to verify the authenticity of the message later.
4. `--armor`: This option specifies that the output should be in ASCII format instead of binary. ASCII armor is a way to represent binary data (such as encrypted messages) in a human-readable format, which is useful for email and other text-based communication methods.
5. `-r recipient@tryhackme.thm`: This option specifies the recipient's email address or key ID. GPG will use the recipient's public key associated with this email address to encrypt the message. This ensures that only the recipient, who possesses the corresponding private key, can decrypt and read the message.
6. `message.txt`: This is the name of the file containing the message you want to encrypt and sign.

Note: GPG uses the `-r` option to specify the recipient's email address, but it doesn't directly use the email address to determine the recipient's key. Instead, GPG relies on its keyring, which is a collection of public keys associated with different email addresses or key IDs.