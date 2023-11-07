
### History Files

If a user accidentally types their password on the command line instead of into a password prompt, it may get recorded in a history file.

View the contents of all the hidden history files in the user's home directory:

```bash
cat ~/.*history | less
```

### Config Files

**Sometimes we would just find a reference to another location where the root user's credentials can be found, so make sure to look on config files whenever you find one.**

### SSH Keys

Sometimes users make backups of important files but fail to secure them with the correct permissions.

Look for hidden files & directories in the system root:

```bash
ls -la /.ssh
```

Sometimes we might find a private key file like the one named `root_key` for example.

we copy the file content to a file we make on our machine, then we change the permission of the file to this `600`:

```bash
chmod 600 root_key
```

Use the key to login note that due to the age of the box, some additional settings are required when using SSH):

```bash
ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@<ip address>
```

