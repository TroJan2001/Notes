 The RSA algorithm (Rivest-Shamir-Adleman) is the basis of a cryptosystem -- a suite of cryptographic algorithms that are used for specific security services or purposes -- which enables public key encryption and is widely used to secure sensitive data, particularly when it is being sent over an insecure network such as the interne
# The math(s) side

RSA is based on the mathematically difficult problem of working out the factors of a large number. It’s very quick to multiply two prime numbers together, say 17*23 = 391, but it’s quite difficult to work out what two prime numbers multiply together to make 14351 (113x127 for reference).

### The attacking side

The maths behind RSA seems to come up relatively often in CTFs, normally requiring you to calculate variables or break some encryption based on them. The wikipedia page for RSA seems complicated at first, but will give you almost all of the information you need in order to complete challenges.

There are some excellent tools for defeating RSA challenges in CTFs, and my personal favorite is [https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) which has worked very well for me. I’ve also had some success with [https://github.com/ius/rsatool](https://github.com/ius/rsatool).

The key variables that you need to know about for RSA in CTFs are p, q, m, n, e, d, and c.

“p” and “q” are large prime numbers, “n” is the product of p and q.

The public key is n and e, the private key is n and d.

“m” is used to represent the message (in plaintext) and “c” represents the ciphertext (encrypted text).

### Algorithm:

RSA got its name from its inventors, Rivest, Shamir, and Adleman. It works as follows:

1. Choose two random prime numbers, _p_ and _q_. Calculate _N_ = _p_ × _q_.
2. Choose two integers _e_ and _d_ such that _e_ × _d_ = 1 mod _ϕ_(_N_), where _ϕ_(_N_) = _N_ − _p_ − _q_ + 1. This step will let us generate the public key (_N_,_e_) and the private key (_N_,_d_).
3. The sender can encrypt a value _x_ by calculating _y_ = x$^e$ mod _N_. (Modulus)
4. The recipient can decrypt _y_ by calculating _x_ = y$^d$ mod _N_. Note that y$^d$ = x$^{ed}$ = x$^{kϕ(N)+1}$ = 
    (x$^{ϕ(N)}$)$^k$ = x. This step explains why we put a restriction on the choice of _e_ and _d_.

RSA security relies on factorization being a hard problem. It is easy to multiply _p_ by _q_; however, it is time-consuming to find _p_ and _q_ given _N_. Moreover, for this to be secure, _p_ and _q_ should be pretty large numbers, for example, each being 1024 bits (that’s a number with more than 300 digits). It is important to note that RSA relies on secure random number generation, as with other asymmetric encryption algorithms. If an adversary can guess _p_ and _q_, the whole system would be considered insecure.

Let’s consider the following practical example.

1. Bob chooses two prime numbers: _p_ = 157 and _q_ = 199. He calculates _N_ = 31243.
2. With _ϕ_(_N_) = _N_ − _p_ − _q_ + 1 = 31243 − 157 − 199 + 1 = 30888, Bob selects _e_ = 163 and _d_ = 379 where _e_ × _d_ = 163 × 379 = 61777 and 61777 mod 30888 = 1. The public key is (31243,163) and the private key is (31243,379).
3. Let’s say that the value to encrypt is _x_ = 13, then Alice would calculate and send _y_ = _x__e_ mod _N_ = 13163 mod 31243 = 16342.
4. Bob will decrypt the received value by calculating _x_ = _y__d_ mod _N_ = 16341379 mod 31243 = 13.

# Useful Commands

To generate a private key:

```bash
openssl genrsa -out private-key.pem 2048
```

To generate a public key from a private key:

```bash
openssl rsa -in private-key.pem -pubout -out public-key.pem writing RSA key
```

To see real RSA variables. The values of p, q, N, e, and d are `prime1`, `prime2`, `modulus`, `publicExponent`, and `privateExponent`, respectively.:

```bash
openssl rsa -in private-key.pem -text -noout
```

To encrypt the file `plaintext.txt` using a public key:

```bash
openssl pkeyutl -encrypt -in plaintext.txt -out ciphertext -inkey public-key.pem -pubin
```

To decrypt the file `ciphertext` using the corresponding private key:

```bash
openssl pkeyutl -decrypt -in ciphertext -inkey private-key.pem -out decrypted.txt
```