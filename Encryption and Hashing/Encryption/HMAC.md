
Hash-based message authentication code (HMAC) is a message authentication code (MAC) that uses a cryptographic key in addition to a hash function.

According to [RFC2104](https://www.rfc-editor.org/rfc/rfc2104), HMAC needs:

- secret key
- inner pad (ipad) a constant string. (RFC2104 uses the byte `0x36` repeated B times. The value of B depends on the chosen hash function.)
- outer pad (opad) a constant string. (RFC2104 uses the byte `0x5C` repeated B times.)

Calculating the HMAC follows the following steps as shown in the figure:

1. Append zeroes to the key to make it of length B, i.e., to make its length match that of the ipad.
2. Using bitwise exclusive-OR (XOR), represented by ⊕, calculate _k__e__y_ ⊕ _i__p__a__d_.
3. Append the message to the XOR output from step 2.
4. Apply the hash function to the resulting stream of bytes (in step 3).
5. Using XOR, calculate _k__e__y_ ⊕ _o__p__a__d_.
6. Append the hash function output from step 4 to the XOR output from step 5.
7. Apply the hash function to the resulting stream of bytes (in step 6) to get the HMAC.

To calculate the HMAC on a Linux system, you can use any of the available tools such as `hmac256` (or `sha224hmac`, `sha256hmac`, `sha384hmac`, and `sha512hmac`, where the secret key is added after the option `--key`). Below we show an example of calculating the HMAC using `hmac256` and `sha256hmac` with two different keys.
# Useful Commands


To calculate the 256bit hash, we can either use `hmac256` like so:

```bash
hmac256 s!Kr37 message.txt
```

or using `sha256hmac`:

```bash
sha256hmac message.txt --key s!Kr37
```