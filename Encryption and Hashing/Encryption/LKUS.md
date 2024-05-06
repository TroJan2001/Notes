Linux Unified Key Setup (LUKS) is a cryptographic disk encryption standard for Linux systems. It uses symmetric and asymmetric encryption to protect data on encrypted disks and partitions. LUKS is a versatile encryption method that can be used to encrypt any block device, including hard drives, USB drives, and even entire operating systems.


To set up LUKS from the command line, the steps are along these lines:

- Install `cryptsetup-luks`. (You can issue `apt install cryptsetup`, `yum install cryptsetup-luks` or `dnf install cryptsetup-luks` for Ubuntu/Debian, RHEL/Cent OS, and Fedora, respectively.)
- Confirm the partition name using `fdisk -l`, `lsblk` or `blkid`. (Create a partition using `fdisk` if necessary.)
- Set up the partition for LUKS encryption: `cryptsetup -y -v luksFormat /dev/sdb1`. (Replace `/dev/sdb1` with the partition name you want to encrypt.)
- Create a mapping to access the partition: `cryptsetup luksOpen /dev/sdb1 EDCdrive`.
- Confirm mapping details: `ls -l /dev/mapper/EDCdrive` and `cryptsetup -v status EDCdrive`.
- Overwrite existing data with zero: `dd if=/dev/zero of=/dev/mapper/EDCdrive`.
- Format the partition: `mkfs.ext4 /dev/mapper/EDCdrive -L "Strategos USB"`.
- Mount it and start using it like a usual partition: `mount /dev/mapper/EDCdrive /media/secure-USB`.
- To check the LUKS setting, you can issue the command `cryptsetup luksDump /dev/sdb1`
- sudo cryptsetup open --type luks `<image file>` `<mapping file>` && sudo mount /dev/mapper/`<mapping file>` `<mapping file>`/