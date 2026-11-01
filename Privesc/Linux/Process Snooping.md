---
title: "Process Snooping"
created: 2026-11-01
type: technique
tags: [technique, privesc, linux, enumeration]
---

## What Is It

Reading running process details with `ps aux` to find secrets (passwords, API keys, tokens) passed as command line arguments. Any user on the system can see every process's full command line.

## How It Works

When a program is started with arguments like:

```bash
./app --password SuperSecret123
```

That full command line is stored in `/proc/<pid>/cmdline` and visible to everyone via `ps`. The program might be running as root, but any low-privilege user can read its arguments.

## Exploitation

```bash
ps aux
ps aux | grep -i pass
ps aux | grep -i key
ps aux | grep -i token
```

For real-time monitoring (catches short-lived processes):

```bash
watch -n 1 'ps aux'
```

Or use `pspy` for monitoring without root:

```bash
./pspy64
```

## Detection / Defense

- Never pass secrets as command line arguments
- Use environment variables: `export DB_PASS=secret`
- Use config files with restricted permissions: `chmod 600 config.ini`
- Use stdin: prompt the user to type it in
- Use a secrets manager (Vault, AWS Secrets Manager)

## Related

- [[Privilege Escalation]]
- [[Enumeration]]
