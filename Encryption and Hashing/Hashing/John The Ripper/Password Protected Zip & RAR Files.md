
We can use John to crack the password on password protected Zip or RAR files. Again, we're going to be using a separate part of the john suite of tools to convert the zip or RAR file into a format that John will understand.


### Zip Files

For zip files we will be using `Zip2John` tool, and the syntax is as follows:

```bash
zip2john [options] [zip file] > [output file]
```

**Note:** `[options]` - Allows you to pass specific checksum options to zip2john, this shouldn't often be necessary.

Example:

```bash
zip2john zipfile.zip > zip_hash.txt
```

Now its ready to be cracked using the following command:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```

### RAR Files

its almost the same for RAR files unless the tool is different, we will be using `Rar2John`, and the syntax is as follows 

```bash
rar2john [rar file] > [output file]
```

Example:

```bash
rar2john rarfile.rar > rar_hash.txt
```

Now its ready to be cracked using the following command:
``
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt
```