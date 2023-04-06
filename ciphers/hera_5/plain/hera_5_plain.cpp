#include "hera_5_plain.h"

#include <math.h>

#include <algorithm>
#include <iostream>

typedef __uint128_t uint128_t;

namespace HERA_5 {

std::vector<uint64_t> HERA::encrypt(std::vector<uint64_t> plaintext) const {
  uint64_t nonce = 123456789;
  size_t size = plaintext.size();

  size_t num_block = ceil((double)size / params.plain_size);

  Hera hera(secret_key, modulus);
  std::vector<uint64_t> ciphertext = plaintext;

  for (uint64_t b = 0; b < num_block; b++) {
    block ks = hera.keystream(nonce, b);
    for (size_t i = b * params.plain_size;
         i < (b + 1) * params.plain_size && i < size; i++)
      ciphertext[i] = (ciphertext[i] + ks[i - b * params.plain_size]) % modulus;
  }

  return ciphertext;
}

std::vector<uint64_t> HERA::decrypt(std::vector<uint64_t> ciphertext) const {
  uint64_t nonce = 123456789;
  size_t size = ciphertext.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  Hera hera(secret_key, modulus);
  std::vector<uint64_t> plaintext = ciphertext;

  for (uint64_t b = 0; b < num_block; b++) {
    block ks = hera.keystream(nonce, b);
    for (size_t i = b * params.cipher_size;
         i < (b + 1) * params.cipher_size && i < size; i++) {
      if (ks[i - b * params.plain_size] > plaintext[i]) plaintext[i] += modulus;
      plaintext[i] = plaintext[i] - ks[i - b * params.plain_size];
    }
  }

  return plaintext;
}

void HERA::prep_one_block() const {
  uint64_t nonce = 123456789;
  Hera hera(modulus);
  hera.preprocess(nonce, 0);
}

//----------------------------------------------------------------

void Hera::init_shake(uint64_t nonce, uint64_t block_counter) {
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

uint64_t Hera::generate_random_field_element() {
  uint8_t random_bytes[sizeof(uint64_t)];
  while (1) {
    if (SUCCESS !=
        Keccak_HashSqueeze(&shake128_, random_bytes, sizeof(random_bytes) * 8))
      throw std::runtime_error("SHAKE128 squeeze failed");
    uint64_t ele = be64toh(*((uint64_t*)random_bytes)) & max_prime_size;
    if (ele < hera_p) return ele;
  }
}

//----------------------------------------------------------------

std::vector<uint64_t> Hera::get_random_vector() {
  std::vector<uint64_t> result;
  result.reserve(HERA_PARAMS.key_size);
  for (auto i = 0ULL; i < HERA_PARAMS.key_size; i++) {
    result.push_back(generate_random_field_element());
  }
  return result;
}

//----------------------------------------------------------------

Hera::Hera(const std::vector<uint64_t>& key, uint64_t modulus)
    : hera_p(modulus), max_prime_size(0) {
  std::copy_n(key.begin(), HERA_PARAMS.key_size, key_.begin());

  while (modulus) {
    max_prime_size++;
    modulus >>= 1;
  }
  max_prime_size = (1ULL << max_prime_size) - 1;
}

//----------------------------------------------------------------

Hera::Hera(uint64_t modulus) : hera_p(modulus), max_prime_size(0) {
  while (modulus) {
    max_prime_size++;
    modulus >>= 1;
  }
  max_prime_size = (1ULL << max_prime_size) - 1;
}

//----------------------------------------------------------------

void Hera::gen_keystream(const uint64_t nonce, const uint64_t block_counter) {
  init_shake(nonce, block_counter);
  state_ = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  ark();
  for (uint8_t r = 1; r < HERA_R; r++) {
    round();
  }
  final_round();
}

//----------------------------------------------------------------

void Hera::preprocess(const uint64_t nonce, const uint64_t block_counter) {
  init_shake(nonce, block_counter);
  std::vector<std::vector<uint64_t>> rcs(HERA_R + 1);

  for (uint8_t r = 0; r <= HERA_R; r++) {
    rcs[r] = get_random_vector();
  }
}

//----------------------------------------------------------------

block Hera::keystream(const uint64_t nonce, const uint64_t block_counter) {
  gen_keystream(nonce, block_counter);
  return state_;
}

//----------------------------------------------------------------

void Hera::round() {
  matmul();
  sbox_cube();
  ark();
}

//----------------------------------------------------------------

void Hera::final_round() {
  matmul();
  sbox_cube();
  matmul();
  ark();
}

//----------------------------------------------------------------

void Hera::ark() {
  for (uint64_t el = 0; el < HERA_PARAMS.key_size; el++) {
    uint64_t mult =
        ((uint128_t)(key_[el]) * generate_random_field_element()) % hera_p;
    // ld(prime) ~ 60, no uint128_t for addition necessary
    state_[el] = (state_[el] + mult) % hera_p;
  }
}

//----------------------------------------------------------------

void Hera::sbox_cube() {
  for (uint16_t el = 0; el < HERA_PARAMS.key_size; el++) {
    uint64_t square = ((uint128_t)(state_[el]) * state_[el]) % hera_p;
    state_[el] = ((uint128_t)(square)*state_[el]) % hera_p;
  }
}

//----------------------------------------------------------------
void Hera::matmul() {
  mix_columns();
  mix_rows();
}

//----------------------------------------------------------------
void Hera::mix_columns() {
  if (HERA_PARAMS.cipher_size != 16) {
    throw std::runtime_error("matrix defined for wrong statesize");
  }

  block new_state;
  new_state.fill(0);
  for (uint8_t c = 0; c < 4; c++) {
    // ld(prime) ~ 60, no uint128_t for addition necessary
    uint64_t sum = (state_[c * 4] + state_[c * 4 + 1]) % hera_p;
    sum = (sum + state_[c * 4 + 2]) % hera_p;
    sum = (sum + state_[c * 4 + 3]) % hera_p;

    for (uint8_t el = 0; el < 4; el++) {
      new_state[c * 4 + el] = (sum + state_[c * 4 + el]) % hera_p;
      new_state[c * 4 + el] =
          (new_state[c * 4 + el] + state_[c * 4 + ((el + 1) % 4)]) % hera_p;
      new_state[c * 4 + el] =
          (new_state[c * 4 + el] + state_[c * 4 + ((el + 1) % 4)]) % hera_p;
    }
  }

  state_ = new_state;
}

//----------------------------------------------------------------
void Hera::mix_rows() {
  if (HERA_PARAMS.cipher_size != 16) {
    throw std::runtime_error("matrix defined for wrong statesize");
  }

  block new_state;
  new_state.fill(0);
  for (uint8_t c = 0; c < 4; c++) {
    uint64_t sum = (state_[c] + state_[c + 4]) % hera_p;
    sum = (sum + state_[c + 8]) % hera_p;
    sum = (sum + state_[c + 12]) % hera_p;

    for (uint8_t el = 0; el < 4; el++) {
      new_state[c + el * 4] = (sum + state_[c + el * 4]) % hera_p;
      new_state[c + el * 4] =
          (new_state[c + el * 4] + state_[c + 4 * ((el + 1) % 4)]) % hera_p;
      new_state[c + el * 4] =
          (new_state[c + el * 4] + state_[c + 4 * ((el + 1) % 4)]) % hera_p;
    }
  }

  state_ = new_state;
}

}  // namespace HERA_5
