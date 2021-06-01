# KREYVIUM-13

Implementation of the Kreyvium stream cipher providng 128 bit security.

This implementation simulates a blockcipher by defining a blocksize of 125 bit with incremented IV for each new block. This has the advantage that the multiplicative depth of the implementations stays constant and is independent of the size of the plaintext.

Code is inspired by the official Kreyvium repository:
[https://github.com/renaud1239/Kreyvium](https://github.com/renaud1239/Kreyvium)
