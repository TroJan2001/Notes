#### ==**Saving metadata to image files**==

ExifTool is used to read and write metadata in various file types, such as JPEG images.

The following are examples of metadata that can be found in the original digital images:
- Camera model / Smartphone model
- Date and time of image capture
- Photo settings such as focal length, aperture, shutter speed, and ISO settings

### Useful commands:

To install pdfinfo :

```bash
sudo apt install libimage-exiftool-perl
```

To read all the EXIF data embedded in an image:

```bash
exiftool IMAGE.jpg
```


