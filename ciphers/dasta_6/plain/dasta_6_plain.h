#pragma once

#include <array>
#include <bitset>
#include <string>
#include <vector>

#include "m4ri/m4ri.h"
#include "../../common/Cipher.h"

namespace DASTA_6 {

constexpr BlockCipherParams DASTA_128_PARAMS = {44, 351, 44, 351, 44, 351};

class DASTA_128 : public BlockCipher {
 public:
  DASTA_128(std::vector<uint8_t> secret_key)
      : BlockCipher(DASTA_128_PARAMS, secret_key) {}

  virtual ~DASTA_128() = default;

  virtual std::string get_cipher_name() const { return "DASTA (n=351,r=6)"; }
  virtual std::vector<uint8_t> encrypt(std::vector<uint8_t> plaintext,
                                       size_t bits) const;
  virtual std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext,
                                       size_t bits) const;

  virtual void prep_one_block() const;
};

//------------------------------------------------------------------------
//------------------------------------------------------------------------
// Dasta CORE
//------------------------------------------------------------------------
//------------------------------------------------------------------------

constexpr size_t blocksize =
    DASTA_128_PARAMS.plain_size_bits;  // Block size in bits
constexpr size_t rounds = 6;           // Number of rounds

typedef __uint128_t uint128_t;
typedef std::bitset<blocksize> block;  // Store messages and states
typedef std::bitset<blocksize> keyblock;

constexpr int CL = 15;
constexpr uint128_t data_limit_sr = 229248395;
const std::array<uint8_t, CL> cycle_lengths = {3,  5,  7,  11, 13, 17, 19, 23,
                                               29, 31, 37, 41, 43, 47, 25};

#include "layer351.h"

class Dasta {
 public:
  Dasta(const keyblock& k = 0) : key(k) {}
  ~Dasta();

  block crypt(const block& message, const uint128_t counter);
  void set_key(const keyblock& k);
  void genInstance(const uint128_t counter, bool m4ri = false);

  std::vector<mzd_t*> m4ri_LinMatrices;
  std::array<block, blocksize> LinMatrix;
  std::array<std::array<uint16_t, blocksize>, rounds + 1> bit_permutation_array;

 private:
  keyblock key = 0;
  block Substitution(const block& input);
  block bitPermutation(const block& input, size_t round);
  block MultiplyWithGF2Matrix(const std::array<block, blocksize>& matrix,
                              const block& input);
};

template <int cl>
class BitPermutation {
 public:
  BitPermutation(std::array<uint8_t, cl> cycle_lengths) {
    this->cycle_lengths = cycle_lengths;
  };
  ~BitPermutation(){};

  void get_power(uint128_t power,
                 std::array<uint16_t, blocksize>& bit_permutation) {
    unsigned int offset = 0, index = 0;
    unsigned int power_mod = 0, current_cl;

    for (unsigned int i = 0; i < cl; i++) {
      current_cl = this->cycle_lengths[i];
      if (power > 0) {
        power_mod = power % current_cl;
      }

      for (unsigned k = 0; k < current_cl; k++) {
        bit_permutation[index] = offset + ((power_mod + k) % current_cl);
        index += 1;
      }
      offset += cycle_lengths[i];
    }
  }

 private:
  std::array<uint8_t, cl> cycle_lengths;
};

}  // namespace DASTA_6
