  
Trusted Platform Module (TPM) and BitLocker are two security features that can be used to protect your data on Windows computers.

- **TPM** is a small chip that is embedded on your computer's motherboard. It provides a secure place to store encryption keys, which are used to protect your data.
- **BitLocker** is a full-disk encryption feature that uses the TPM to encrypt your computer's hard drive. This means that even if someone steals your computer, they will not be able to access your data without the encryption keys.

**TPM** does the following:

- Stores encryption keys in a secure location
- Verifies the integrity of the computer's boot process
- Provides a secure random number generator

**BitLocker** does the following:

- Encrypts the entire hard drive
- Requires a password or PIN to unlock the drive
- Supports recovery keys in case you forget your password

**TPM** is not required for BitLocker to work, but it is recommended. Without a TPM, BitLocker will require you to use a USB drive to store the encryption keys. This is less secure than storing the keys on the TPM.

**Here is a table that summarizes the differences between TPM and BitLocker:**


![](../Attachments/Pasted%20image%2020231105010425.png)
**Question:** What must a user insert on computers that **DO NOT** have a TPM version 1.2 or later?
**USB startup key** 