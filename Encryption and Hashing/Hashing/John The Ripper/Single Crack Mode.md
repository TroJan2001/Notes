In this mode, John uses only the information provided in the username, to try and work out possible passwords heuristically, by slightly changing the letters and numbers contained within the username.

To use single crack mode, and if we wanted to crack the password of the user named "Mike", we'd use:  

```bash
john --single --format=[format] [path to file]
```

**A Note on File Formats in Single Crack Mode:**

If you're cracking hashes in single crack mode, you need to change the file format that you're feeding john for it to understand what data to create a wordlist from. You do this by prepending the hash with the username that the hash belongs to, for example- we would change the file hashes.txt

**From:**  

`1efee03cdcb96d90ad48ccc7b8666033`

**To**

`mike:1efee03cdcb96d90ad48ccc7b8666033`