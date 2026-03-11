ssh2john converts the id_rsa private key that you use to login to the SSH session into hash format that john can work with, since we might need to unencrypt it if it is encrypted with a passphrase.
# Useful commands:

To convert the id_rsa private key into hash format that john can work with:

```bash
ssh2john [id_rsa private key file] > [output file]
```

Now to crack the passphrase we can use this command:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
```