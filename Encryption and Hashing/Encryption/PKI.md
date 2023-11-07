# Useful Commands

 To generate a certificate signing request we use this command:
 
```bash
openssl req -new -nodes -newkey rsa:4096 -keyout key.pem -out cert.csr
```

- `req -new` create a new certificate signing request
- `-nodes` save private key without a passphrase
- `-newkey` generate a new private key
- `rsa:4096` generate an RSA key of size 4096 bits
- `-keyout` specify where to save the key
- `-out` save the certificate signing request

To generate a self-signed certificate:

```bash
openssl req -x509 -newkey -nodes rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365
```

The `-x509` indicates that we want to generate a self-signed certificate instead of a certificate request. The `-sha256` specifies the use of the SHA-256 digest. It will be valid for one year as we added `-days 365`.

To view a certificate:

```bash
openssl x509 -in cert.pem -text
```