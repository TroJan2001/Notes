#### ==**Recover lost files based on their headers, footers, and internal data structures**==

Foremost is a program that recovers files based on their headers , footers and internal data structures , I find it useful when dealing with png images.
# Useful commands

To extract data from the given file:

```bash
foremost -i file
```

Search for a selection of file types (`-t doc,jpg,pdf,xls`) in the given image file (`-i image.dd`): 

```bash
foremost -t doc,jpg,pdf,xls -i image.dd
```
