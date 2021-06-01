#include "pasta_4_plain.h"

#include <math.h>

typedef __uint128_t uint128_t;

namespace PASTA_4 {

std::vector<uint64_t> PASTA::encrypt(std::vector<uint64_t> plaintext) const {
  uint64_t nonce = 123456789;
  size_t size = plaintext.size();

  size_t num_block = ceil((double)size / params.plain_size);

  Pasta pasta(secret_key, modulus);
  std::vector<uint64_t> ciphertext = plaintext;

  for (uint64_t b = 0; b < num_block; b++) {
    block ks = pasta.keystream(nonce, b);
    for (size_t i = b * params.plain_size;
         i < (b + 1) * params.plain_size && i < size; i++)
      ciphertext[i] = (ciphertext[i] + ks[i - b * params.plain_size]) % modulus;
  }

  return ciphertext;
}

std::vector<uint64_t> PASTA::decrypt(std::vector<uint64_t> ciphertext) const {
  uint64_t nonce = 123456789;
  size_t size = ciphertext.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  Pasta pasta(secret_key, modulus);
  std::vector<uint64_t> plaintext = ciphertext;

  for (uint64_t b = 0; b < num_block; b++) {
    block ks = pasta.keystream(nonce, b);
    for (size_t i = b * params.cipher_size;
         i < (b + 1) * params.cipher_size && i < size; i++) {
      if (ks[i - b * params.plain_size] > plaintext[i]) plaintext[i] += modulus;
      plaintext[i] = plaintext[i] - ks[i - b * params.plain_size];
    }
  }

  return plaintext;
}

void PASTA::prep_one_block() const {
  uint64_t nonce = 123456789;
  Pasta pasta(modulus);
  pasta.preprocess(nonce, 0);
}

//----------------------------------------------------------------
void Pasta::init_shake(uint64_t nonce, uint64_t block_counter) {
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

uint64_t Pasta::generate_random_field_element(bool allow_zero) {
  uint8_t random_bytes[sizeof(uint64_t)];
  while (1) {
    if (SUCCESS !=
        Keccak_HashSqueeze(&shake128_, random_bytes, sizeof(random_bytes) * 8))
      throw std::runtime_error("SHAKE128 squeeze failed");
    uint64_t ele = be64toh(*((uint64_t*)random_bytes)) & max_prime_size;
    if (!allow_zero && ele == 0) continue;
    if (ele < pasta_p) return ele;
  }
}

//----------------------------------------------------------------

std::vector<uint64_t> Pasta::calculate_row(
    const std::vector<uint64_t>& prev_row,
    const std::vector<uint64_t>& first_row) {
  std::vector<uint64_t> out(PASTA_T);
  for (auto j = 0ULL; j < PASTA_T; j++) {
    uint64_t tmp =
        ((uint128_t)(first_row[j]) * prev_row[PASTA_T - 1]) % pasta_p;
    if (j) {
      // ld(rasta_prime) ~ 60, no uint128_t for addition necessary
      tmp = (tmp + prev_row[j - 1]) % pasta_p;
    }
    out[j] = tmp;
  }
  return out;
}

//----------------------------------------------------------------
// (0  1  0  ... 0 ) ^ t
// (0  0  1  ... 0 )
// (.  .  .  ... . )
// (.  .  .  ... . )
// (.  .  .  ... . )
// (0  0  0 ...  1 )
// (r1 r2 r3 ... rt)
// invertible by design
std::vector<std::vector<uint64_t>> Pasta::get_random_matrix() {
  std::vector<std::vector<uint64_t>> mat(PASTA_T,
                                         std::vector<uint64_t>(PASTA_T));
  mat[0] = get_random_vector(false);
  for (auto i = 1ULL; i < PASTA_T; i++) {
    mat[i] = calculate_row(mat[i - 1], mat[0]);
  }
  return mat;
}

//----------------------------------------------------------------

std::vector<uint64_t> Pasta::get_random_vector(bool allow_zero) {
  std::vector<uint64_t> rc(PASTA_T, 0);
  for (uint16_t i = 0; i < PASTA_T; i++) {
    rc[i] = generate_random_field_element(allow_zero);
  }
  return rc;
}

//----------------------------------------------------------------

Pasta::Pasta(const std::vector<uint64_t>& key, uint64_t modulus)
    : key_(key), max_prime_size(0), pasta_p(modulus) {
  uint64_t p = pasta_p;
  while (p) {
    max_prime_size++;
    p >>= 1;
  }
  max_prime_size = (1ULL << max_prime_size) - 1;
}

//----------------------------------------------------------------

Pasta::Pasta(uint64_t modulus) : max_prime_size(0), pasta_p(modulus) {
  uint64_t p = pasta_p;
  while (p) {
    max_prime_size++;
    p >>= 1;
  }
  max_prime_size = (1ULL << max_prime_size) - 1;
}

//----------------------------------------------------------------

block Pasta::gen_keystream(const uint64_t nonce, const uint64_t block_counter) {
  init_shake(nonce, block_counter);

  // init state
  for (uint16_t i = 0; i < PASTA_T; i++) {
    state1_[i] = key_[i];
    state2_[i] = key_[PASTA_T + i];
  }

  for (uint8_t r = 0; r < PASTA_R; r++) {
    round(r);
  }
  // final affine with mixing afterwards
  linear_layer();
  return state1_;
}

//----------------------------------------------------------------

block Pasta::keystream(const uint64_t nonce, const uint64_t block_counter) {
  return gen_keystream(nonce, block_counter);
}

//----------------------------------------------------------------

void Pasta::preprocess(const uint64_t nonce, const uint64_t block_counter) {
  init_shake(nonce, block_counter);
  std::vector<std::vector<std::vector<uint64_t>>> mats1(PASTA_R + 1);
  std::vector<std::vector<std::vector<uint64_t>>> mats2(PASTA_R + 1);
  std::vector<std::vector<uint64_t>> rcs1(PASTA_R + 1);
  std::vector<std::vector<uint64_t>> rcs2(PASTA_R + 1);

  for (uint8_t r = 0; r <= PASTA_R; r++) {
    mats1[r] = get_random_matrix();
    mats2[r] = get_random_matrix();
    rcs1[r] = get_random_vector();
    rcs2[r] = get_random_vector();
  }
}

//----------------------------------------------------------------

void Pasta::round(size_t r) {
  linear_layer();
  if (r == PASTA_R - 1) {
    sbox_cube(state1_);
    sbox_cube(state2_);
  } else {
    sbox_feistel(state1_);
    sbox_feistel(state2_);
  }
}

//----------------------------------------------------------------

void Pasta::linear_layer() {
  matmul(state1_);
  matmul(state2_);
  add_rc(state1_);
  add_rc(state2_);
  mix();
}

//----------------------------------------------------------------

void Pasta::add_rc(block& state) {
  for (uint16_t el = 0; el < PASTA_T; el++) {
    // ld(rasta_prime) ~ 60, no uint128_t for addition necessary
    state[el] = (state[el] + generate_random_field_element()) % pasta_p;
  }
}

//----------------------------------------------------------------

void Pasta::sbox_cube(block& state) {
  for (uint16_t el = 0; el < PASTA_T; el++) {
    uint64_t square = ((uint128_t)(state[el]) * state[el]) % pasta_p;
    state[el] = ((uint128_t)(square)*state[el]) % pasta_p;
  }
}

//----------------------------------------------------------------

void Pasta::sbox_feistel(block& state) {
  block new_state;
  new_state[0] = state[0];
  for (uint16_t el = 1; el < PASTA_T; el++) {
    uint64_t square = ((uint128_t)(state[el - 1]) * state[el - 1]) % pasta_p;
    // ld(rasta_prime) ~ 60, no uint128_t for addition necessary
    new_state[el] = (square + state[el]) % pasta_p;
  }
  state = new_state;
}

//----------------------------------------------------------------
// (2 1)(state1_)
// (1 2)(state2_)

void Pasta::mix() {
  // just adding
  for (uint16_t i = 0; i < PASTA_T; i++) {
    // ld(rasta_prime) ~ 60, no uint128_t for addition necessary
    uint64_t sum = (state1_[i] + state2_[i]) % pasta_p;
    state1_[i] = (state1_[i] + sum) % pasta_p;
    state2_[i] = (state2_[i] + sum) % pasta_p;
  }
}

//----------------------------------------------------------------
// requires storage of two rows in the matrix
void Pasta::matmul(block& state) {
  block new_state;
  new_state.fill(0);

  std::vector<uint64_t> rand = get_random_vector(false);
  std::vector<uint64_t> curr_row = rand;

  for (uint16_t i = 0; i < PASTA_T; i++) {
    for (uint16_t j = 0; j < PASTA_T; j++) {
      uint64_t mult = ((uint128_t)(curr_row[j]) * state[j]) % pasta_p;
      // ld(rasta_prime) ~ 60, no uint128_t for addition necessary
      new_state[i] = (new_state[i] + mult) % pasta_p;
    }
    if (i != PASTA_T - 1) curr_row = calculate_row(curr_row, rand);
  }
  state = new_state;
}

//----------------------------------------------------------------

std::vector<uint64_t> Pasta::get_rc_vec(size_t vecsize) {
  std::vector<uint64_t> rc(vecsize + PASTA_T, 0);
  for (uint16_t i = 0; i < PASTA_T; i++) {
    rc[i] = generate_random_field_element();
  }
  for (uint16_t i = vecsize; i < vecsize + PASTA_T; i++) {
    rc[i] = generate_random_field_element();
  }
  return rc;
}

}  // namespace PASTA_4
