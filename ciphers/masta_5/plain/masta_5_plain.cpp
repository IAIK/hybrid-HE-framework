#include "masta_5_plain.h"

#include <math.h>

#include <algorithm>
#include <iostream>

typedef __uint128_t uint128_t;

namespace MASTA_5 {

std::vector<uint64_t> MASTA_128::encrypt(
    std::vector<uint64_t> plaintext) const {
  uint64_t nonce = 123456789;
  size_t size = plaintext.size();

  size_t num_block = ceil((double)size / params.plain_size);

  Masta masta(secret_key, modulus);
  std::vector<uint64_t> ciphertext = plaintext;

  for (uint64_t b = 0; b < num_block; b++) {
    block ks = masta.keystream(nonce, b);
    for (size_t i = b * params.plain_size;
         i < (b + 1) * params.plain_size && i < size; i++)
      ciphertext[i] = (ciphertext[i] + ks[i - b * params.plain_size]) % modulus;
  }

  return ciphertext;
}

std::vector<uint64_t> MASTA_128::decrypt(
    std::vector<uint64_t> ciphertext) const {
  uint64_t nonce = 123456789;
  size_t size = ciphertext.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  Masta masta(secret_key, modulus);
  std::vector<uint64_t> plaintext = ciphertext;

  for (uint64_t b = 0; b < num_block; b++) {
    block ks = masta.keystream(nonce, b);
    for (size_t i = b * params.cipher_size;
         i < (b + 1) * params.cipher_size && i < size; i++) {
      if (ks[i - b * params.plain_size] > plaintext[i]) plaintext[i] += modulus;
      plaintext[i] = plaintext[i] - ks[i - b * params.plain_size];
    }
  }

  return plaintext;
}

void MASTA_128::prep_one_block() const {
  uint64_t nonce = 123456789;
  Masta masta(modulus);
  masta.preprocess(nonce, 0);
}

//----------------------------------------------------------------

void Masta::init_shake(uint64_t nonce, uint64_t block_counter) {
  uint8_t seed[16];

  *((uint64_t*)seed) = htobe64(nonce);
  *((uint64_t*)(seed + 8)) = htobe64(block_counter);

  if (SUCCESS != Keccak_HashInitialize_SHAKE128(&shake128_))
    throw std::runtime_error("failed to init shake");
  if (SUCCESS != Keccak_HashUpdate(&shake128_, seed, sizeof(seed) * 8))
    throw std::runtime_error("SHAKE128 update failed");
  if (SUCCESS != Keccak_HashFinal(&shake128_, NULL))
    throw std::runtime_error("SHAKE128 final failed");
}

//----------------------------------------------------------------

uint64_t Masta::generate_random_field_element() {
  uint8_t random_bytes[sizeof(uint64_t)];
  while (1) {
    if (SUCCESS !=
        Keccak_HashSqueeze(&shake128_, random_bytes, sizeof(random_bytes) * 8))
      throw std::runtime_error("SHAKE128 squeeze failed");
    uint64_t ele = be64toh(*((uint64_t*)random_bytes)) & max_prime_size;
    if (ele < masta_p) return ele;
  }
}

//----------------------------------------------------------------

std::vector<uint64_t> Masta::get_random_vector() {
  std::vector<uint64_t> result;
  result.reserve(MASTA_128_PARAMS.key_size);
  for (auto i = 0ULL; i < MASTA_128_PARAMS.key_size; i++) {
    result.push_back(generate_random_field_element());
  }
  return result;
}

//----------------------------------------------------------------

std::vector<std::vector<uint64_t>> Masta::get_random_matrix() {
  // Matrix for multiplication in F_p^n with (X^n - ALPHA) as reduction
  // polynomial
  std::vector<std::vector<uint64_t>> result(
      MASTA_128_PARAMS.key_size,
      std::vector<uint64_t>(MASTA_128_PARAMS.key_size));

  std::vector<uint64_t> field_element = get_random_vector();

  for (auto col = 0ULL; col < MASTA_128_PARAMS.key_size; col++) {
    for (auto row = 0ULL; row < MASTA_128_PARAMS.key_size; row++) {
      ssize_t ind = ((ssize_t)row - col);
      if (ind < 0)
        result[row][col] =
            ((uint128_t)(field_element[ind + MASTA_128_PARAMS.key_size]) *
             MASTA_ALPHA) %
            masta_p;
      else
        result[row][col] = field_element[ind];
    }
  }
  return result;
}

//----------------------------------------------------------------

Masta::Masta(const std::vector<uint64_t>& key, uint64_t modulus)
    : masta_p(modulus), max_prime_size(0) {
  std::copy_n(key.begin(), MASTA_128_PARAMS.key_size, key_.begin());

  while (modulus) {
    max_prime_size++;
    modulus >>= 1;
  }
  max_prime_size = (1ULL << max_prime_size) - 1;
}

//----------------------------------------------------------------

Masta::Masta(uint64_t modulus) : masta_p(modulus), max_prime_size(0) {
  while (modulus) {
    max_prime_size++;
    modulus >>= 1;
  }
  max_prime_size = (1ULL << max_prime_size) - 1;
}

//----------------------------------------------------------------

void Masta::gen_keystream(const uint64_t nonce, const uint64_t block_counter) {
  init_shake(nonce, block_counter);
  state_ = key_;

  for (uint8_t r = 0; r < MASTA_R; r++) {
    round();
  }
  matmul();
  add_rc();

  keyadd();
}

//----------------------------------------------------------------

block Masta::keystream(const uint64_t nonce, const uint64_t block_counter) {
  gen_keystream(nonce, block_counter);
  return state_;
}

//----------------------------------------------------------------

void Masta::preprocess(const uint64_t nonce, const uint64_t block_counter) {
  init_shake(nonce, block_counter);
  std::vector<std::vector<std::vector<uint64_t>>> mats(MASTA_R + 1);
  std::vector<std::vector<uint64_t>> rcs(MASTA_R + 1);

  for (uint8_t r = 0; r <= MASTA_R; r++) {
    mats[r] = get_random_matrix();
    rcs[r] = get_random_vector();
  }
}

//----------------------------------------------------------------

void Masta::round() {
  matmul();
  add_rc();
  sbox();
}

//----------------------------------------------------------------

void Masta::add_rc() {
  for (uint64_t el = 0; el < MASTA_128_PARAMS.key_size; el++) {
    state_[el] = (state_[el] + generate_random_field_element()) % masta_p;
  }
}

//----------------------------------------------------------------

void Masta::sbox() {
  block new_state = state_;
  for (uint64_t el = 0; el < MASTA_128_PARAMS.key_size; el++) {
    size_t ind1 = (el + 1) % MASTA_128_PARAMS.key_size;
    size_t ind2 = (ind1 + 1) % MASTA_128_PARAMS.key_size;
    uint64_t mult = ((uint128_t)(state_[ind1]) * state_[ind2]) % masta_p;
    new_state[el] += (state_[ind2] + mult) % masta_p;
    new_state[el] %= masta_p;
  }
  state_ = new_state;
}

//----------------------------------------------------------------

void Masta::matmul() {
  block new_state;
  new_state.fill(0);

  std::vector<std::vector<uint64_t>> mat = get_random_matrix();

  for (uint64_t i = 0; i < MASTA_128_PARAMS.key_size; i++) {
    for (uint64_t j = 0; j < MASTA_128_PARAMS.key_size; j++) {
      uint64_t mult = ((uint128_t)(mat[i][j]) * state_[j]) % masta_p;
      // ld(masta_prime) ~ 60, no uint128_t for addition necessary
      new_state[i] = (new_state[i] + mult) % masta_p;
    }
  }
  state_ = new_state;
}

//----------------------------------------------------------------

void Masta::keyadd() {
  for (uint64_t el = 0; el < MASTA_128_PARAMS.key_size; el++) {
    state_[el] = (state_[el] + key_[el]) % masta_p;
  }
}

}  // namespace MASTA_5
