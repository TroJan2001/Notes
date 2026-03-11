By default, SSH is authenticated using usernames and passwords. But. we can also authenticate using public and private keys, using `ssh-keygen` program to generate the pair.

We can encrypt the private key with a passphrase too so in case a baddie got an access to this file he wouldn't access the private key itself but an encrypted version of it to make it more secure. Using tools like John the Ripper, you can attack an encrypted SSH key to attempt to find the passphrase, which highlights the importance of using a secure passphrase and keeping your private key private.
# How to use these keys:

The ~/.ssh folder is the default place to store these keys for OpenSSH. The `authorized_keys` (note the US English spelling) file in this directory holds public keys that are allowed to access the server if key authentication is enabled. By default on many distros, key authentication is enabled as it is more secure than using a password to authenticate. Normally for the root user, only key authentication is enabled.

In order to use a private SSH key, the permissions must be set up correctly otherwise your SSH client will ignore the file with a warning. Only the owner should be able to read or write to the private key (600 or stricter). `ssh -i keyNameGoesHere user@host` is how you specify a key for the standard Linux OpenSSH client.
# Using SSH keys to get a better shell

SSH keys are an excellent way to “upgrade” a reverse shell, assuming the user has login enabled (www-data normally does not, but regular users and root will). Leaving an SSH key in authorized_keys on a box can be a useful backdoor, and you don't need to deal with any of the issues of unstabilised reverse shells like Control-C or lack of tab completion.
# Authenticate using SSH keys

First, upload the id_rsa.pub file to /home/USER/.ssh/id_rsa.pub (if .ssh is not there, create it) using the following command:

```bash
echo id_rsa.pub >> authorized_keys
```

Then, on the attacker, run:

```bash
ssh -i id_rsa VICTIM@TARGET
#id_rsa is the private key
```