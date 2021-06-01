#include "lowmc_plain.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <vector>

namespace LOWMC {

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

block ctr(const block& iv, uint64_t ctr) {
  block out = iv;
  for (size_t i = blocksize - 64; i < blocksize; i++) {
    out[i] = iv[i] ^ ((ctr >> (blocksize - i - 1)) & 1);
  }
  return out;
}

std::vector<uint8_t> LOWMC_256_128_63_14::encrypt(
    std::vector<uint8_t> plaintext, size_t bits) const {
  keyblock key = convert_key(secret_key);

  size_t num_block = ceil((double)bits / params.plain_size_bits);

  LowMC lowmc(key);
  std::vector<block> plain = convert_in(plaintext, num_block);
  std::vector<block> result;
  result.reserve(plain.size());

  block iv = 0;
  for (uint64_t i = 0; i < num_block; i++) {
    result.push_back(plain[i] ^ lowmc.encrypt(ctr(iv, i + 1)));
  }

  return convert_out(result, plaintext.size());
}

std::vector<uint8_t> LOWMC_256_128_63_14::decrypt(
    std::vector<uint8_t> ciphertext, size_t bits) const {
  keyblock key = convert_key(secret_key);

  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  LowMC lowmc(key);
  std::vector<block> ciph = convert_in(ciphertext, num_block);
  std::vector<block> result;
  result.reserve(ciph.size());

  block iv = 0;
  for (uint64_t i = 0; i < num_block; i++) {
    result.push_back(ciph[i] ^ lowmc.encrypt(ctr(iv, i + 1)));
  }

  return convert_out(result, ciphertext.size());
}

void LOWMC_256_128_63_14::prep_one_block() const { LowMC lowmc; }

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

/////////////////////////////
//     LowMC functions     //
/////////////////////////////

block LowMC::encrypt(const block message) {
  block c = message ^ roundkeys[0];
  for (unsigned r = 1; r <= rounds; ++r) {
    c = Substitution(c);
    c = MultiplyWithGF2Matrix(LinMatrices[r - 1], c);
    c ^= roundconstants[r - 1];
    c ^= roundkeys[r];
  }
  return c;
}

block LowMC::decrypt(const block message) {
  block c = message;
  for (unsigned r = rounds; r > 0; --r) {
    c ^= roundkeys[r];
    c ^= roundconstants[r - 1];
    c = MultiplyWithGF2Matrix(invLinMatrices[r - 1], c);
    c = invSubstitution(c);
  }
  c ^= roundkeys[0];
  return c;
}

void LowMC::set_key(keyblock k) {
  key = k;
  keyschedule();
}

void LowMC::print_matrices() {
  std::cout << "LowMC matrices and constants" << std::endl;
  std::cout << "============================" << std::endl;
  std::cout << "Block size: " << blocksize << std::endl;
  std::cout << "Key size: " << keysize << std::endl;
  std::cout << "Rounds: " << rounds << std::endl;
  std::cout << std::endl;

  std::cout << "Linear layer matrices" << std::endl;
  std::cout << "---------------------" << std::endl;
  for (unsigned r = 1; r <= rounds; ++r) {
    std::cout << "Linear layer " << r << ":" << std::endl;
    for (auto row : LinMatrices[r - 1]) {
      std::cout << "[";
      for (unsigned i = 0; i < blocksize; ++i) {
        std::cout << row[i];
        if (i != blocksize - 1) {
          std::cout << ", ";
        }
      }
      std::cout << "]" << std::endl;
    }
    std::cout << std::endl;
  }

  std::cout << "Round constants" << std::endl;
  std::cout << "---------------------" << std::endl;
  for (unsigned r = 1; r <= rounds; ++r) {
    std::cout << "Round constant " << r << ":" << std::endl;
    std::cout << "[";
    for (unsigned i = 0; i < blocksize; ++i) {
      std::cout << roundconstants[r - 1][i];
      if (i != blocksize - 1) {
        std::cout << ", ";
      }
    }
    std::cout << "]" << std::endl;
    std::cout << std::endl;
  }

  std::cout << "Round key matrices" << std::endl;
  std::cout << "---------------------" << std::endl;
  for (unsigned r = 0; r <= rounds; ++r) {
    std::cout << "Round key matrix " << r << ":" << std::endl;
    for (auto row : KeyMatrices[r]) {
      std::cout << "[";
      for (unsigned i = 0; i < keysize; ++i) {
        std::cout << row[i];
        if (i != keysize - 1) {
          std::cout << ", ";
        }
      }
      std::cout << "]" << std::endl;
    }
    if (r != rounds) {
      std::cout << std::endl;
    }
  }
}

/////////////////////////////
// LowMC private functions //
/////////////////////////////

block LowMC::Substitution(const block message) {
  block temp = 0;
  // Get the identity part of the message
  temp ^= (message >> 3 * numofboxes);
  // Get the rest through the Sboxes
  for (unsigned i = 1; i <= numofboxes; ++i) {
    temp <<= 3;
    temp ^= Sbox[((message >> 3 * (numofboxes - i)) & block(0x7)).to_ulong()];
  }
  return temp;
}

block LowMC::invSubstitution(const block message) {
  block temp = 0;
  // Get the identity part of the message
  temp ^= (message >> 3 * numofboxes);
  // Get the rest through the invSboxes
  for (unsigned i = 1; i <= numofboxes; ++i) {
    temp <<= 3;
    temp ^=
        invSbox[((message >> 3 * (numofboxes - i)) & block(0x7)).to_ulong()];
  }
  return temp;
}

block LowMC::MultiplyWithGF2Matrix(const std::vector<block> matrix,
                                   const block message) {
  block temp = 0;
  for (unsigned i = 0; i < blocksize; ++i) {
    temp[i] = (message & matrix[i]).count() % 2;
  }
  return temp;
}

block LowMC::MultiplyWithGF2Matrix_Key(const std::vector<keyblock> matrix,
                                       const keyblock k) {
  block temp = 0;
  for (unsigned i = 0; i < blocksize; ++i) {
    temp[i] = (k & matrix[i]).count() % 2;
  }
  return temp;
}

void LowMC::keyschedule() {
  roundkeys.clear();
  for (unsigned r = 0; r <= rounds; ++r) {
    roundkeys.push_back(MultiplyWithGF2Matrix_Key(KeyMatrices[r], key));
  }
  return;
}

void LowMC::instantiate_LowMC(bool m4ri) {
  // Create LinMatrices and invLinMatrices
  state.reset();
  LinMatrices.clear();
  invLinMatrices.clear();
  for (unsigned r = 0; r < rounds; ++r) {
    // Create matrix
    std::vector<block> mat;
    // Fill matrix with random bits
    do {
      mat.clear();
      for (unsigned i = 0; i < blocksize; ++i) {
        mat.push_back(getrandblock());
      }
      // Repeat if matrix is not invertible
    } while (rank_of_Matrix(mat) != blocksize);
    LinMatrices.push_back(mat);
    invLinMatrices.push_back(invert_Matrix(LinMatrices.back()));
  }

  // Create roundconstants
  roundconstants.clear();
  for (unsigned r = 0; r < rounds; ++r) {
    roundconstants.push_back(getrandblock());
  }

  // Create KeyMatrices
  KeyMatrices.clear();
  for (unsigned r = 0; r <= rounds; ++r) {
    // Create matrix
    std::vector<keyblock> mat;
    // Fill matrix with random bits
    do {
      mat.clear();
      for (unsigned i = 0; i < blocksize; ++i) {
        mat.push_back(getrandkeyblock());
      }
      // Repeat if matrix is not of maximal rank
    } while (rank_of_Matrix_Key(mat) < std::min(blocksize, keysize));
    KeyMatrices.push_back(mat);
  }

  if (!m4ri) return;

  m4ri_LinMatrices.reserve(rounds);
  m4ri_invLinMatrices.reserve(rounds);

  for (unsigned r = 0; r < rounds; ++r) {
    mzd_t* mat = mzd_init(blocksize, blocksize);
    mzd_t* inv_mat = mzd_init(blocksize, blocksize);
    for (rci_t i = 0; i < (rci_t)blocksize; i++) {
      for (rci_t j = 0; j < (rci_t)blocksize; j++) {
        mzd_write_bit(mat, i, j, LinMatrices[r][i][j]);
        mzd_write_bit(inv_mat, i, j, invLinMatrices[r][i][j]);
      }
    }
    m4ri_LinMatrices.push_back(mat);
    m4ri_invLinMatrices.push_back(inv_mat);
  }

  m4ri_KeyMatrices.reserve(rounds + 1);

  for (unsigned r = 0; r <= rounds; ++r) {
    mzd_t* mat = mzd_init(blocksize, keysize);
    for (rci_t i = 0; i < (rci_t)blocksize; i++) {
      for (rci_t j = 0; j < (rci_t)keysize; j++)
        mzd_write_bit(mat, i, j, KeyMatrices[r][i][j]);
    }
    m4ri_KeyMatrices.push_back(mat);
  }
}

LowMC::~LowMC() {
  for (auto& i : m4ri_LinMatrices) mzd_free(i);
  for (auto& i : m4ri_invLinMatrices) mzd_free(i);
  for (auto& i : m4ri_KeyMatrices) mzd_free(i);
}

/////////////////////////////
// Binary matrix functions //
/////////////////////////////

unsigned LowMC::rank_of_Matrix(const std::vector<block> matrix) {
  std::vector<block> mat;  // Copy of the matrix
  for (auto u : matrix) {
    mat.push_back(u);
  }
  unsigned size = mat[0].size();
  // Transform to upper triangular matrix
  unsigned row = 0;
  for (unsigned col = 1; col <= size; ++col) {
    if (!mat[row][size - col]) {
      unsigned r = row;
      while (r < mat.size() && !mat[r][size - col]) {
        ++r;
      }
      if (r >= mat.size()) {
        continue;
      } else {
        auto temp = mat[row];
        mat[row] = mat[r];
        mat[r] = temp;
      }
    }
    for (unsigned i = row + 1; i < mat.size(); ++i) {
      if (mat[i][size - col]) mat[i] ^= mat[row];
    }
    ++row;
    if (row == size) break;
  }
  return row;
}

unsigned LowMC::rank_of_Matrix_Key(const std::vector<keyblock> matrix) {
  std::vector<keyblock> mat;  // Copy of the matrix
  for (auto u : matrix) {
    mat.push_back(u);
  }
  unsigned size = mat[0].size();
  // Transform to upper triangular matrix
  unsigned row = 0;
  for (unsigned col = 1; col <= size; ++col) {
    if (!mat[row][size - col]) {
      unsigned r = row;
      while (r < mat.size() && !mat[r][size - col]) {
        ++r;
      }
      if (r >= mat.size()) {
        continue;
      } else {
        auto temp = mat[row];
        mat[row] = mat[r];
        mat[r] = temp;
      }
    }
    for (unsigned i = row + 1; i < mat.size(); ++i) {
      if (mat[i][size - col]) mat[i] ^= mat[row];
    }
    ++row;
    if (row == size) break;
  }
  return row;
}

std::vector<block> LowMC::invert_Matrix(const std::vector<block> matrix) {
  std::vector<block> mat;  // Copy of the matrix
  for (auto u : matrix) {
    mat.push_back(u);
  }
  std::vector<block> invmat(blocksize, 0);  // To hold the inverted matrix
  for (unsigned i = 0; i < blocksize; ++i) {
    invmat[i][i] = 1;
  }

  unsigned size = mat[0].size();
  // Transform to upper triangular matrix
  unsigned row = 0;
  for (unsigned col = 0; col < size; ++col) {
    if (!mat[row][col]) {
      unsigned r = row + 1;
      while (r < mat.size() && !mat[r][col]) {
        ++r;
      }
      if (r >= mat.size()) {
        continue;
      } else {
        auto temp = mat[row];
        mat[row] = mat[r];
        mat[r] = temp;
        temp = invmat[row];
        invmat[row] = invmat[r];
        invmat[r] = temp;
      }
    }
    for (unsigned i = row + 1; i < mat.size(); ++i) {
      if (mat[i][col]) {
        mat[i] ^= mat[row];
        invmat[i] ^= invmat[row];
      }
    }
    ++row;
  }

  // Transform to identity matrix
  for (unsigned col = size; col > 0; --col) {
    for (unsigned r = 0; r < col - 1; ++r) {
      if (mat[r][col - 1]) {
        mat[r] ^= mat[col - 1];
        invmat[r] ^= invmat[col - 1];
      }
    }
  }

  return invmat;
}

///////////////////////
// Pseudorandom bits //
///////////////////////

block LowMC::getrandblock() {
  block tmp = 0;
  for (unsigned i = 0; i < blocksize; ++i) tmp[i] = getrandbit();
  return tmp;
}

keyblock LowMC::getrandkeyblock() {
  keyblock tmp = 0;
  for (unsigned i = 0; i < keysize; ++i) tmp[i] = getrandbit();
  return tmp;
}

// Uses the Grain LSFR as self-shrinking generator to create pseudorandom bits
// Is initialized with the all 1s state
// The first 160 bits are thrown away
bool LowMC::getrandbit() {
  bool tmp = 0;
  // If state has not been initialized yet
  if (state.none()) {
    state.set();  // Initialize with all bits set
    // Throw the first 160 bits away
    for (unsigned i = 0; i < 160; ++i) {
      // Update the state
      tmp =
          state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
      state >>= 1;
      state[79] = tmp;
    }
  }
  // choice records whether the first bit is 1 or 0.
  // The second bit is produced if the first bit is 1.
  bool choice = false;
  do {
    // Update the state
    tmp = state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
    state >>= 1;
    state[79] = tmp;
    choice = tmp;
    tmp = state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
    state >>= 1;
    state[79] = tmp;
  } while (!choice);
  return tmp;
}

}  // namespace LOWMC
