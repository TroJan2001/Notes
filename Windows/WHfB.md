
### Windows Hello for Business

The procedure to store a new pair of certificates with WHfB:

1. Trusted Platform Module (TPM) public-private key pair generation: The TPM creates a public-private key pair for the user's account when they enrol. It's crucial to remember that the private key never leaves the TPM and is never disclosed.  
2. Client certificate request: The client initiates a certificate request to receive a trustworthy certificate. The organisation's certificate issuing authority (CA) receives this request and provides a valid certificate.
3. Key storage: The user account's `msDS-KeyCredentialLink` attribute will be set.

Authentication Process:

1. Authorisation: The Domain Controller decrypts the client's pre-authentication data using the raw public key stored in the `msDS-KeyCredentialLink` attribute of the user's account.
2. Certificate generation: The certificate is created for the user by the Domain Controller and can be sent back to the client.
3. Authentication: After that, the client can log in to the Active Directory domain using the certificate.