#pragma once

#include <bitset>
#include <string>
#include <vector>

#include "m4ri/m4ri.h"
#include "../../common/Cipher.h"

namespace LOWMC {

constexpr BlockCipherParams LOWMC_256_128_63_14_PARAMS = {16,  128, 32,
                                                          256, 32,  256};

class LOWMC_256_128_63_14 : public BlockCipher {
 public:
  LOWMC_256_128_63_14(std::vector<uint8_t> secret_key)
      : BlockCipher(LOWMC_256_128_63_14_PARAMS, secret_key) {}

  virtual ~LOWMC_256_128_63_14() = default;

  virtual std::string get_cipher_name() const {
    return "LOWMC (n=256,k=128,m=63,r=14,d=128)";
  }
  virtual std::vector<uint8_t> encrypt(std::vector<uint8_t> plaintext,
                                       size_t bits) const;
  virtual std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext,
                                       size_t bits) const;

  virtual void prep_one_block() const;
};

/*
Code below taken from the official LowMC github (https://github.com/lowmc/lowmc)
with the following LICENCE

The MIT License (MIT)

Copyright (c) 2016 tyti

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

constexpr unsigned numofboxes = 63;  // Number of Sboxes
constexpr unsigned blocksize =
    LOWMC_256_128_63_14_PARAMS.plain_size_bits;  // Block size in bits
constexpr unsigned keysize =
    LOWMC_256_128_63_14_PARAMS.key_size_bits;  // Key size in bits
constexpr unsigned rounds = 14;                // Number of rounds

constexpr unsigned identitysize = blocksize - 3 * numofboxes;
// Size of the identity part in the Sbox layer

typedef std::bitset<blocksize> block;  // Store messages and states
typedef std::bitset<keysize> keyblock;

block ctr(const block& iv, uint64_t ctr);

class LowMC {
 public:
  LowMC(keyblock k) {
    key = k;
    instantiate_LowMC();
    keyschedule();
  };

  // special constructor for an instance containing only matrices for HE
  LowMC(bool m4ri = false) { instantiate_LowMC(m4ri); }

  ~LowMC();

  block encrypt(const block message);
  block decrypt(const block message);
  void set_key(keyblock k);

  void print_matrices();

  // LowMC private data members //
  // The Sbox and its inverse
  const std::vector<unsigned> Sbox = {0x00, 0x01, 0x03, 0x06,
                                      0x07, 0x04, 0x05, 0x02};
  const std::vector<unsigned> invSbox = {0x00, 0x01, 0x07, 0x02,
                                         0x05, 0x06, 0x03, 0x04};
  std::vector<std::vector<block>> LinMatrices;
  // Stores the binary matrices for each round
  std::vector<std::vector<block>> invLinMatrices;
  // Stores the inverses of LinMatrices
  std::vector<block> roundconstants;
  // Stores the round constants
  std::vector<std::vector<keyblock>> KeyMatrices;
  // Stores the matrices that generate the round keys

  std::vector<mzd_t*> m4ri_LinMatrices;
  std::vector<mzd_t*> m4ri_invLinMatrices;
  std::vector<mzd_t*> m4ri_KeyMatrices;

 private:
  keyblock key = 0;
  // Stores the master key
  std::vector<block> roundkeys;
  // Stores the round keys

  // LowMC private functions //
  block Substitution(const block message);
  // The substitution layer
  block invSubstitution(const block message);
  // The inverse substitution layer

  block MultiplyWithGF2Matrix(const std::vector<block> matrix,
                              const block message);
  // For the linear layer
  block MultiplyWithGF2Matrix_Key(const std::vector<keyblock> matrix,
                                  const keyblock k);
  // For generating the round keys

  void keyschedule();
  // Creates the round keys from the master key

  void instantiate_LowMC(bool m4ri = false);
  // Fills the matrices and roundconstants with pseudorandom bits

  // Binary matrix functions //
  unsigned rank_of_Matrix(const std::vector<block> matrix);
  unsigned rank_of_Matrix_Key(const std::vector<keyblock> matrix);
  std::vector<block> invert_Matrix(const std::vector<block> matrix);

  // Random bits functions //
  block getrandblock();
  keyblock getrandkeyblock();
  bool getrandbit();

  std::bitset<80> state;  // Keeps the 80 bit LSFR state
};

}  // namespace LOWMC
