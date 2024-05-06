# Hidden files inside images
 
 Steganography is hiding a file or a message inside of another file , there are many fun steganography CTF challenges out there where the flag is hidden in an image , audio file or even other types of files.
 
 The very first tool there looks to be useful. It can be used to extract embedded data from JPEG files.
# Useful commands: 

Displays info about a file whether it has embedded data or not:
 
```bash
steghide info file 
```

To extract embedded data from a file:
 
```bash
steghide extract -sf <file>
```

To brute force steghide passphrase:

```bash
stegcracker <filename> <wordlist>
```
Here is a list of very useful tools and resources:

https://0xrick.github.io/lists/stego/
