#include "rasta_6_packed_plain.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <vector>

#include "math.h"

namespace RASTA_6_PACKED {

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

std::vector<uint8_t> RASTA_128::encrypt(std::vector<uint8_t> plaintext,
                                        size_t bits) const {
  keyblock key = convert_key(secret_key);

  size_t num_block = ceil((double)bits * 8 / params.plain_size_bits);

  std::vector<block> plain = convert_in(plaintext, num_block);
  std::vector<block> result;
  result.reserve(plain.size());

  Rasta rasta(key);

  for (size_t i = 0; i < num_block; i++)
    result.push_back(rasta.crypt(plain[i], 0, i + 1));

  return convert_out(result, plaintext.size());
}

std::vector<uint8_t> RASTA_128::decrypt(std::vector<uint8_t> ciphertext,
                                        size_t bits) const {
  keyblock key = convert_key(secret_key);

  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  std::vector<block> ciph = convert_in(ciphertext, num_block);
  std::vector<block> result;
  result.reserve(ciph.size());

  Rasta rasta(key);
  for (size_t i = 0; i < num_block; i++)
    result.push_back(rasta.crypt(ciph[i], 0, i + 1));

  return convert_out(result, ciphertext.size());
}

void RASTA_128::prep_one_block() const {
  Rasta rasta;
  rasta.genInstance(0, 1);
}

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

/////////////////////////////
//     Rasta functions     //
/////////////////////////////

block Rasta::crypt(const block message, const UINT64 nonce,
                   const UINT64 counter) {
  // Only public values involved in instance generation
  switch (instance_) {
    case randall:
      generate_Instance_randall(nonce, counter);
      break;
    case lu:
      generate_Instance_lu(nonce, counter);
      break;
    default:
      generate_Instance_all_new(nonce, counter);
      break;
  }

  // Secret key is used after instance generation
  block c = key;
  for (unsigned r = 1; r <= rounds; ++r) {
    c = MultiplyWithGF2Matrix(LinMatrices[r - 1], c);
    c ^= roundconstants[r - 1];
    c = Substitution(c);
  }
  c = MultiplyWithGF2Matrix(LinMatrices[rounds], c);
  c ^= roundconstants[rounds];
  c ^= key;
  c ^= message;
  return c;
}

void Rasta::genInstance(const UINT64 nonce, const UINT64 counter) {
  // Only public values involved in instance generation
  switch (instance_) {
    case randall:
      generate_Instance_randall(nonce, counter);
      break;
    case lu:
      generate_Instance_lu(nonce, counter);
      break;
    default:
      generate_Instance_all_new(nonce, counter);
      break;
  }

  LinMatrices_u8.reserve(rounds + 1);
  roundconstants_u8.reserve(rounds + 1);

  for (unsigned r = 0; r <= rounds; ++r) {
    std::vector<uint8_t> constants(blocksize);
    std::vector<std::vector<uint8_t>> mat(blocksize,
                                          std::vector<uint8_t>(blocksize));
    for (unsigned i = 0; i < blocksize; i++) {
      constants[i] = roundconstants[r][i];
      for (unsigned j = 0; j < blocksize; j++) {
        mat[i][j] = LinMatrices[r][i][j];
      }
    }
    LinMatrices_u8.push_back(std::move(mat));
    roundconstants_u8.push_back(std::move(constants));
  }
}

void Rasta::set_key(keyblock k) { key = k; }

/////////////////////////////
// Rasta private functions //
/////////////////////////////

block Rasta::Substitution(const block x) {
  block temp = 0;
  block xp1 = (x >> 1) | (x << (blocksize - 1));
  block xp2 = (x >> 2) | (x << (blocksize - 2));

  temp = x ^ xp2 ^ (xp1 & xp2);

  return temp;
}

block Rasta::MultiplyWithGF2Matrix(const std::vector<block> matrix,
                                   const block message) {
  block temp = 0;
  for (unsigned i = 0; i < blocksize; ++i) {
    temp[i] = (message & matrix[i]).count() % 2;
  }
  return temp;
}

std::vector<block> Rasta::MultiplyGF2Matrix(const std::vector<block> A,
                                            const std::vector<block> B) {
  std::vector<block> tempmat;

  for (unsigned i = 0; i < blocksize; ++i) {
    block row = 0;
    for (unsigned j = 0; j < blocksize; ++j) {
      block temp = 0;
      for (unsigned k = 0; k < blocksize; ++k) {
        temp[k] = (A[i][k] & B[k][j]);
      }
      row[j] = temp.count() % 2;
    }
    tempmat.push_back(row);
  }
  return tempmat;
}

std::vector<block> Rasta::MultiplyGF2MatrixTransposed(
    const std::vector<block> A, const std::vector<block> B) {
  std::vector<block> tempmat;
  for (unsigned i = 0; i < blocksize; ++i) {
    block row = 0;
    for (unsigned j = 0; j < blocksize; ++j) {
      row[j] = (A[i] & B[j]).count() % 2;
    }
    tempmat.push_back(row);
  }
  return tempmat;
}

void Rasta::generate_Instance_all_new(const UINT64 nonce,
                                      const UINT64 counter) {
  // Initialize RNG state
  initrand(nonce, counter);
  // Create LinMatrices and invLinMatrices
  LinMatrices.clear();
  for (unsigned r = 0; r <= rounds; ++r) {
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
  }

  // Create roundconstants
  roundconstants.clear();
  for (unsigned r = 0; r <= rounds; ++r) {
    roundconstants.push_back(getrandblock());
  }

  return;
}

void Rasta::generate_Instance_lu(const UINT64 nonce, const UINT64 counter) {
  // Initialize RNG state
  initrand(nonce, counter);
  // Create LinMatrices and roundconstants
  LinMatrices.clear();
  roundconstants.clear();
  for (unsigned r = 0; r <= rounds; ++r) {
    // Create matrix
    std::vector<block> mat1, mat2;
    // Fill matrix with random bits
    mat1.clear();
    mat2.clear();
    for (unsigned i = 1; i <= blocksize; ++i) {
      mat1.push_back(getrandblockfirstone(i));
      mat2.push_back(getrandblockfirstone(blocksize - i + 1));
    }
    //      std::cout << "Rank: " <<
    //      rank_of_Matrix(MultiplyGF2MatrixTransposed(mat1, mat2)) <<
    //      std::endl;
    LinMatrices.push_back(MultiplyGF2MatrixTransposed(mat1, mat2));
    roundconstants.push_back(getrandblock());
  }

  return;
}

void Rasta::generate_Instance_randall(const UINT64 nonce,
                                      const UINT64 counter) {
  // Initialize RNG state
  initrand(nonce, counter);
  // Create LinMatrices and roundconstants
  LinMatrices.clear();
  roundconstants.clear();
  for (unsigned round = 0; round <= rounds; ++round) {
    // Create matrix
    std::vector<block> A;
    std::vector<block> T;
    block indexes;
    // Fill matrix with random bits
    A.clear();
    T.clear();
    for (unsigned int i = 0; i < blocksize; ++i) {
      A.push_back(0);
      T.push_back(0);
      indexes[i] = 1;
    }
    for (unsigned int i = 0; i < blocksize; ++i) {
      unsigned int first_one = blocksize - i;
      while (first_one == blocksize - i) {
        for (first_one = 0; first_one < blocksize - i; first_one++) {
          if (getrandbit()) break;
        }
      }
      unsigned int r = 0;
      unsigned int count = 0;
      for (r = 0; r < blocksize; ++r) {
        if (indexes[r]) count++;
        if (first_one + 1 == count) {
          indexes[r] = 0;
          T[r][r] = 1;
          A[i][r] = 1;
          break;
        }
      }
      for (unsigned int j = r + 1; j < blocksize; ++j) {
        if (indexes[j])
          //        changed rows and columns for easier multiplication
          T[j][r] = getrandbit();
      }
      for (unsigned int j = i + 1; j < blocksize; ++j) {
        A[j][r] = getrandbit();
      }
    }
    //    std::cout << "Rank: " <<
    //    rank_of_Matrix(MultiplyGF2MatrixTransposed(A,T)) << std::endl;
    LinMatrices.push_back(MultiplyGF2MatrixTransposed(A, T));
    roundconstants.push_back(getrandblock());
  }

  return;
}

/////////////////////////////
// Binary matrix functions //
/////////////////////////////

unsigned Rasta::rank_of_Matrix(const std::vector<block> matrix) {
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

///////////////////////
// Pseudorandom bits //
///////////////////////

block Rasta::getrandblock() {
  block tmp = 0;
  for (unsigned i = 0; i < blocksize; ++i) tmp[i] = getrandbit();
  return tmp;
}

block Rasta::getrandblockfirstone(const unsigned int length) {
  block tmp = 0;
  unsigned i;
  for (i = blocksize - 1; i > blocksize - length; i--) tmp[i] = getrandbit();
  tmp[i] = 1;
  return tmp;
}

// Shake like rand functions

void Rasta::initrand(const UINT64 nonce, const UINT64 counter) {
  for (int i = 0; i < 200; ++i) shakestate[i] = 0;

  for (int i = 0; i < 8; ++i)
    shakestate[i] = (rounds >> ((8 * i) % (sizeof(rounds) * 8))) & 0xff;

  for (int i = 8; i < 16; ++i)
    shakestate[i] = (blocksize >> ((8 * i) % (sizeof(blocksize) * 8))) & 0xff;

  for (int i = 24; i < 32; ++i)
    shakestate[i] = (nonce >> ((8 * i) % (sizeof(nonce) * 8))) & 0xff;

  for (int i = 40; i < 48; ++i)
    shakestate[i] = (counter >> ((8 * i) % (sizeof(counter) * 8))) & 0xff;

  shakestate[32] = 0x1F;

  shakestate[shakerate / 8 - 1] ^= 0x80;

  KeccakF1600_StatePermute(shakestate);
  squeezedbits = 0;
}

bool Rasta::getrandbit() {
  bool tmp = 0;
  tmp = (bool)((shakestate[squeezedbits / 8] >> (squeezedbits % 8)) & 1);
  squeezedbits++;
  if (squeezedbits == shakerate) {
    KeccakF1600_StatePermute(shakestate);
    squeezedbits = 0;
  }
  return tmp;
}

// Shake taken from Keccak Code package

#define ROL64(a, offset) \
  ((((UINT64)a) << offset) ^ (((UINT64)a) >> (64 - offset)))
#define fun(x, y) ((x) + 5 * (y))
#define readLane(x, y) (((tKeccakLane*)state)[fun(x, y)])
#define writeLane(x, y, lane) (((tKeccakLane*)state)[fun(x, y)]) = (lane)
#define XORLane(x, y, lane) (((tKeccakLane*)state)[fun(x, y)]) ^= (lane)

int Rasta::LFSR86540(UINT8* LFSR) {
  int result = ((*LFSR) & 0x01) != 0;
  if (((*LFSR) & 0x80) != 0)
    /* Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
    (*LFSR) = ((*LFSR) << 1) ^ 0x71;
  else
    (*LFSR) <<= 1;
  return result;
}

void Rasta::KeccakF1600_StatePermute(void* state) {
  unsigned int round, x, y, j, t;
  UINT8 LFSRstate = 0x01;

  for (round = 0; round < 24; round++) {
    { /* === θ step (see [Keccak Reference, Section 2.3.2]) === */
      tKeccakLane C[5], D;

      /* Compute the parity of the columns */
      for (x = 0; x < 5; x++)
        C[x] = readLane(x, 0) ^ readLane(x, 1) ^ readLane(x, 2) ^
               readLane(x, 3) ^ readLane(x, 4);
      for (x = 0; x < 5; x++) {
        /* Compute the θ effect for a given column */
        D = C[(x + 4) % 5] ^ ROL64(C[(x + 1) % 5], 1);
        /* Add the θ effect to the whole column */
        for (y = 0; y < 5; y++) XORLane(x, y, D);
      }
    }

    { /* === ρ and π steps (see [Keccak Reference, Sections 2.3.3 and 2.3.4])
         === */
      tKeccakLane current, temp;
      /* Start at coordinates (1 0) */
      x = 1;
      y = 0;
      current = readLane(x, y);
      /* Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23 */
      for (t = 0; t < 24; t++) {
        /* Compute the rotation constant r = (t+1)(t+2)/2 */
        unsigned int r = ((t + 1) * (t + 2) / 2) % 64;
        /* Compute ((0 1)(2 3)) * (x y) */
        unsigned int Y = (2 * x + 3 * y) % 5;
        x = y;
        y = Y;
        /* Swap current and state(x,y), and rotate */
        temp = readLane(x, y);
        writeLane(x, y, ROL64(current, r));
        current = temp;
      }
    }

    { /* === χ step (see [Keccak Reference, Section 2.3.1]) === */
      tKeccakLane temp[5];
      for (y = 0; y < 5; y++) {
        /* Take a copy of the plane */
        for (x = 0; x < 5; x++) temp[x] = readLane(x, y);
        /* Compute χ on the plane */
        for (x = 0; x < 5; x++)
          writeLane(x, y, temp[x] ^ ((~temp[(x + 1) % 5]) & temp[(x + 2) % 5]));
      }
    }

    { /* === ι step (see [Keccak Reference, Section 2.3.5]) === */
      for (j = 0; j < 7; j++) {
        unsigned int bitPosition = (1 << j) - 1; /* 2^j-1 */
        if (LFSR86540(&LFSRstate)) XORLane(0, 0, (tKeccakLane)1 << bitPosition);
      }
    }
  }
}

}  // namespace RASTA_6_PACKED
