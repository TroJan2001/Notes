---
title: "md5sum"
created: 2026-03-11
type: tool
tags: [tool, hashing, integrity]
---

# md5sum

Computes or verifies MD5 checksums for file integrity. Used to confirm a file hasn't been modified — compare the hash before and after transfer, or against a known-good value.

---

## Generate a Hash

```bash
md5sum file.txt
```

Output: `c6779ec2960296ed9a04f08d67f64422  file.txt`

## Verify Against a Checksum File

```bash
md5sum -c checksums.md5
```

The checksum file format is `<hash>  <filename>` (two spaces). `-c` reads each line and reports OK or FAILED.

## Hash Multiple Files

```bash
md5sum file1.txt file2.txt file3.txt > checksums.md5
```

---

## Flags

| Flag | Purpose |
|------|---------|
| `-c` | Check hashes from a file |
| `-b` | Binary mode |
| `--quiet` | Only show failures during check |
| `--status` | Exit code only, no output |

---

## SHA Equivalents

Same syntax, stronger algorithms:

| Command | Algorithm | Output Length |
|---------|-----------|-------------|
| `md5sum` | MD5 | 32 hex chars |
| `sha1sum` | SHA-1 | 40 hex chars |
| `sha256sum` | SHA-256 | 64 hex chars |
| `sha512sum` | SHA-512 | 128 hex chars |

For verifying downloads, prefer `sha256sum` — MD5 is vulnerable to collisions.

---

## Related Notes

- [[Password Hashing]] — MD5 for passwords (don't)
- [[Hashcat]] / [[John Basics]] — cracking MD5 hashes
