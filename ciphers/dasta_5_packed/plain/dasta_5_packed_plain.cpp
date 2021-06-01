#include "dasta_5_packed_plain.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <vector>

#include "math.h"

namespace DASTA_5_PACKED {

static keyblock convert_key(const std::vector<uint8_t>& key) {
  keyblock k;
  for (size_t i = 0; i < k.size(); i++) {
    k[i] = (key[i / 8] >> (7 - i % 8)) & 1;
  }
  return k;
}

static std::vector<block> convert_in(const std::vector<uint8_t>& plain,
                                     size_t num_block) {
  std::vector<block> out;
  out.reserve(num_block);

  for (size_t i = 0; i < num_block; i++) {
    block p;
    for (size_t k = 0; k < p.size(); k++) {
      size_t ind = (i * blocksize + k);
      p[k] = (plain[ind / 8] >> (7 - ind % 8)) & 1;
    }
    out.push_back(std::move(p));
  }
  return out;
}

static std::vector<uint8_t> convert_out(const std::vector<block>& cipher,
                                        size_t bytes) {
  std::vector<uint8_t> result(bytes, 0);

  for (size_t i = 0; i < cipher.size(); i++) {
    for (size_t k = 0; k < blocksize; k++) {
      size_t ind = (i * blocksize + k);
      if (ind / 8 >= result.size()) return result;
      result[ind / 8] |= (cipher[i][k] << (7 - ind % 8));
    }
  }
  return result;
}

std::vector<uint8_t> DASTA_128::encrypt(std::vector<uint8_t> plaintext,
                                        size_t bits) const {
  keyblock key = convert_key(secret_key);

  size_t num_block = ceil((double)bits * 8 / params.plain_size_bits);

  std::vector<block> plain = convert_in(plaintext, num_block);
  std::vector<block> result;
  result.reserve(plain.size());

  Dasta dasta(key);

  for (size_t i = 0; i < num_block; i++)
    result.push_back(dasta.crypt(plain[i], i));

  return convert_out(result, plaintext.size());
}

std::vector<uint8_t> DASTA_128::decrypt(std::vector<uint8_t> ciphertext,
                                        size_t bits) const {
  keyblock key = convert_key(secret_key);

  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  std::vector<block> ciph = convert_in(ciphertext, num_block);
  std::vector<block> result;
  result.reserve(ciph.size());

  Dasta dasta(key);
  for (size_t i = 0; i < num_block; i++)
    result.push_back(dasta.crypt(ciph[i], i));

  return convert_out(result, ciphertext.size());
}

void DASTA_128::prep_one_block() const {
  Dasta dasta;
  dasta.genInstance(0);
}

//------------------------------------------------------------------------
//------------------------------------------------------------------------
// Dasta CORE
//------------------------------------------------------------------------
//------------------------------------------------------------------------

block Dasta::crypt(const block& message, const uint128_t counter) {
  // Only public values involved in instance generation
  genInstance(counter);

  // Secret key is used after instance generation
  block c = key;
  for (unsigned r = 1; r <= rounds; ++r) {
    c = bitPermutation(c, r - 1);
    c = MultiplyWithGF2Matrix(LinMatrix, c);
    c = Substitution(c);
  }
  c = bitPermutation(c, rounds);
  c = MultiplyWithGF2Matrix(LinMatrix, c);
  c ^= key;
  c ^= message;
  return c;
}

void Dasta::genInstance(const uint128_t counter) {
  // Only public values involved in instance generation
  BitPermutation<19> permutation_generator1(cycle_lengths1);
  BitPermutation<11> permutation_generator2(cycle_lengths2);

  uint128_t subcounter1 = counter % data_limit_sr;
  uint128_t subcounter2 = counter / data_limit_sr;

  permutation_generator1.get_power(counter, bit_permutation_array[0]);
  permutation_generator2.get_power(subcounter1, bit_permutation_array[2]);
  permutation_generator2.get_power(subcounter2, bit_permutation_array[3]);

  for (size_t i = 0; i < blocksize; i++) {
    bit_permutation_array[1][i] = bit_permutation_array[0][i];
    bit_permutation_array[4][i] = bit_permutation_array[2][i];
    bit_permutation_array[5][i] = bit_permutation_array[3][i];
  }

  // convert matrix
  for (size_t i = 0; i < blocksize; i++) {
    for (size_t j = 0; j < blocksize; j++) {
      LinMatrix[i][j] = linear_layer[blocksize - i - 1][blocksize - j - 1];
    }
  }

  LinMatrices_u8.reserve(rounds + 1);

  for (unsigned r = 0; r <= rounds; ++r) {
    std::vector<std::vector<uint8_t>> mat(blocksize,
                                          std::vector<uint8_t>(blocksize));
    for (unsigned i = 0; i < blocksize; i++) {
      for (unsigned j = 0; j < blocksize; j++) {
        mat[i][j] = LinMatrix[bit_permutation_array[r][i]][j];
      }
    }
    LinMatrices_u8.push_back(std::move(mat));
  }
}

void Dasta::set_key(const keyblock& k) { key = k; }

block Dasta::Substitution(const block& input) {
  block temp = 0;
  block xp1 = (input >> 1) | (input << (blocksize - 1));
  block xp2 = (input >> 2) | (input << (blocksize - 2));

  temp = input ^ xp2 ^ (xp1 & xp2);

  return temp;
}

block Dasta::bitPermutation(const block& input, size_t round) {
  block temp = 0;
  for (unsigned i = 0; i < blocksize; ++i) {
    temp[bit_permutation_array[round][i]] = input[i];
  }
  return temp;
}

block Dasta::MultiplyWithGF2Matrix(const std::array<block, blocksize>& matrix,
                                   const block& input) {
  block temp = 0;
  for (unsigned i = 0; i < blocksize; ++i) {
    temp[i] = (input & matrix[i]).count() % 2;
  }
  return temp;
}

}  // namespace DASTA_5_PACKED
