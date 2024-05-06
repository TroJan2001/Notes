Diffie–Hellman key exchange establishes a shared secret between two parties that can be used for secret communication for exchanging data over a public network.

### The math(s) side:

1. Alice and Bob agree on q and g. For this to work, q should be a prime number, and g is a number smaller than q that satisfies certain conditions. (In modular arithmetic, g is a generator.) In this example, we take q = 29 and g = 3.
2. Alice chooses a random number _a_ smaller than q. She calculates A = (g$^a$) mod q. The number a must be kept a secret; however, A is sent to Bob. Let’s say that Alice picks the number _a_ = 13 and calculates _A_ = 3$^{13}$%29 = 19 and sends it to Bob.
3. Bob picks a random number b smaller than q. He calculates _B_ = (g$^b$) mod _q_. Bob must keep b a secret; however, he sends B to Alice. Let’s consider the case where Bob chooses the number b = 15 and calculates B = 3$^{15}$%29 = 26. He proceeds to send it to Alice.
4. Alice receives B and calculates key = B$^a$ mod q. Numeric example key = 26$^{13}$ mod 29 = 10.
5. Bob receives A and calculates key = A$^b$ mod q. Numeric example key = 19$^{15}$ mod 29 = 10.

# Useful Commands

To generate DH parameters:

```bash
openssl dhparam -out dhparams.pem 2048
#Also we can use 4096
```

To view the prime number `P` and the generator `G` we can use this command:

```bash
openssl dhparam -in dhparams.pem -text -noout
```
