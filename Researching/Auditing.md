
One of the efficient command-line tools to audit system logs on a Linux system is `aureport`.

# Useful Commands

To get logs summary, we can use the following command:

```bash
aureport --summary
```

To get the failed events:

```bash
aureport --failed
```

To get successful or failed logins:

```bash
#Successful
ausearch --message USER_LOGIN --success yes --interpret
#Failed
ausearch --message USER_LOGIN --success no --interpret
```

To get failed logins for a specific account, root account for example:

```bash
ausearch --message USER_LOGIN --success no --interpret | grep ct=root
```

To return only number of lines in the previous commands instead of a very long list:

```bash
ausearch --message USER_LOGIN --success no --interpret | grep ct=root | wc -l
#Another format
ausearch -m USER_LOGIN -sv no -i | grep ct=root | wc -l
```