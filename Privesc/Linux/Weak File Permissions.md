Lets talk about wild vulnerabilities that take place in security due to weak file permissions:
# Readable /etc/shadow

If the shadow file is readable by users, we can view the content using `cat /etc/shadow`, then we would just copy the hash of any user we want to crack its hash to a txt file and then use john the ripper to crack it using the following commands:

```bash
echo '$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0' > hash.txt & john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
# Writable /etc/shadow

We could just generate a password hash and replace the password hash of any user with the one we generated.

```bash
mkpasswd -m sha-512 newpasswordhere
```

and then we use `nano` or `vim` to edit the `/etc/shadow` file
# Writable /etc/passwd

After Enumerating using LinEnum or linpeas, we might find some misconfigured file configuration, like making a specific user a a member of root group noting that the `/etc/passwd` file is writable by users of the root group. This allow us to add a new entry to the `/etc/passwd` file by accessing that user which has high privileges (member of the root group) and making the new entry a root user.

Before we add our new user, we first need to create a compliant password hash to add! We do this by using the command: 

```bash
openssl passwd -1 -salt <salt> <password>
```

For example if we want to make "123" password with the salt "new", we can get the following hash `$1$new$p7ptkEKU1HnaHpRtzNizS1`

Finally we must add the entry according to this syntax `test:x:0:0:root:/root:/bin/bash` if we want to add a root user, for our example the entry should look like this: `new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash`.
# Extra: Understanding /etc/passwd

The /etc/passwd file stores essential information, which  is required during login. In other words, it stores user account information. The /etc/passwd is a plain text file. It contains a list of the system’s accounts, giving for each account some useful information like user ID, group ID, home directory, shell, and more.

The /etc/passwd file should have general read permission as many command utilities use it to map user IDs to user names. However, write access to the /etc/passwd must only limit for the superuser/root account. When it doesn't, or a user has erroneously been added to a write-allowed group. We have a vulnerability that can allow the creation of a root user that we can access.

Understanding /etc/passwd format

The /etc/passwd file contains one entry per line for each user (user account) of the system. All fields are separated by a colon : symbol. Total of seven fields as follows. Generally, /etc/passwd file entry looks as follows:

    test:x:0:0:root:/root:/bin/bash

Username: It is used when user logs in. It should be between 1 and 32 characters in length.
Password: An x character indicates that encrypted password is stored in /etc/shadow file. Please note that you need to use the passwd command to compute the hash of a password typed at the CLI or to store/update the hash of the password in /etc/shadow file, in this case, the password hash is stored as an "x".
User ID (UID): Each user must be assigned a user ID (UID). UID 0 (zero) is reserved for root and UIDs 1-99 are reserved for other predefined accounts. Further UID 100-999 are reserved by system for administrative and system accounts/groups.
Group ID (GID): The primary group ID (stored in /etc/group file)
User ID Info: The comment field. It allow you to add extra information about the users such as user’s full name, phone number etc. This field use by finger command.
Home directory: The absolute path to the directory the user will be in when they log in. If this directory does not exists then users directory becomes /
Command/shell: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell.