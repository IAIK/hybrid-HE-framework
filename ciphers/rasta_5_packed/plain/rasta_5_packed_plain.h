#pragma once

#include <bitset>
#include <string>
#include <vector>

#include "../../common/Cipher.h"

namespace RASTA_5_PACKED {

constexpr BlockCipherParams RASTA_128_PARAMS = {66, 525, 66, 525, 66, 525};

class RASTA_128 : public BlockCipher {
 public:
  RASTA_128(std::vector<uint8_t> secret_key)
      : BlockCipher(RASTA_128_PARAMS, secret_key) {}

  virtual ~RASTA_128() = default;

  virtual std::string get_cipher_name() const { return "RASTA (n=525,r=5)"; }
  virtual std::vector<uint8_t> encrypt(std::vector<uint8_t> plaintext,
                                       size_t bits) const;
  virtual std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext,
                                       size_t bits) const;

  virtual void prep_one_block() const;
};

/*
Code below taken from the official RASTA github
(https://github.com/iaikkrypto/rasta) with the following LICENCE

The MIT License (MIT)

Copyright (c) 2016

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

const unsigned blocksize =
    RASTA_128_PARAMS.plain_size_bits;  // Block size in bits
const unsigned rounds = 5;             // Number of rounds

typedef std::bitset<blocksize> block;  // Store messages and states
typedef std::bitset<blocksize> keyblock;
typedef unsigned long long int UINT64;
typedef UINT64 tKeccakLane;
typedef unsigned char UINT8;
enum instanceGeneration { all_new, lu, randall };

class Rasta {
 public:
  Rasta(keyblock k = 0, instanceGeneration instance = all_new) {
    key = k;
    instance_ = instance;
    squeezedbits = 0;
  };

  ~Rasta(){};

  block crypt(const block message, const UINT64 nonce, const UINT64 counter);
  void set_key(keyblock k);
  instanceGeneration instance_;

  void genInstance(const UINT64 nonce, const UINT64 counter);

  // Rasta private data members //
  std::vector<std::vector<block>> LinMatrices;
  std::vector<std::vector<std::vector<uint8_t>>> LinMatrices_u8;
  // Stores the binary matrices for each round
  std::vector<block> roundconstants;
  std::vector<std::vector<uint8_t>> roundconstants_u8;
  // Stores the round constants
 private:
  keyblock key = 0;
  // Stores the master key

  // Shake private data members
  UINT8 shakestate[200];
  static const unsigned int shakerate = 1088;
  unsigned int squeezedbits;

  // Shake private functions
  void KeccakF1600_StatePermute(void *state);
  int LFSR86540(UINT8 *LFSR);

  // Rasta private functions //
  block Substitution(const block x);
  // The substitution layer

  block MultiplyWithGF2Matrix(const std::vector<block> matrix,
                              const block message);
  std::vector<block> MultiplyGF2Matrix(const std::vector<block> A,
                                       const std::vector<block> B);
  std::vector<block> MultiplyGF2MatrixTransposed(const std::vector<block> A,
                                                 const std::vector<block> B);
  // For the linear layer

  void generate_Instance_all_new(const UINT64 nonce, const UINT64 counter);
  void generate_Instance_lu(const UINT64 nonce, const UINT64 counter);
  void generate_Instance_randall(const UINT64 nonce, const UINT64 counter);
  // Fills the matrices and roundconstants with pseudorandom bits

  // Binary matrix functions //
  unsigned rank_of_Matrix(const std::vector<block> matrix);

  // Random bits functions //
  void initrand(const UINT64 nonce, const UINT64 counter);
  block getrandblock();
  block getrandblockfirstone(const unsigned int length);
  bool getrandbit();
};

}  // namespace RASTA_5_PACKED
