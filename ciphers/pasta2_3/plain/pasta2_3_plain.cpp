#include "pasta2_3_plain.h"
#include <iostream>
#include <chrono>
#include <math.h>

typedef __uint128_t uint128_t;
std::chrono::high_resolution_clock::time_point time_start, time_end;
std::chrono::microseconds time_diff;
namespace PASTA2_3 {

PASTA2::PASTA2(std::vector<uint64_t> secret_key, uint64_t modulus)
    : ZpCipher(PASTA2_PARAMS, secret_key, modulus), instance(modulus) {}

//----------------------------------------------------------------
std::vector<uint64_t> PASTA2::encrypt(std::vector<uint64_t> plaintext) const {
  uint64_t nonce = 123456789;
  size_t size = plaintext.size();

  size_t num_block = ceil((double)size / params.plain_size);

  Pasta2 pasta2(secret_key, instance);
  std::vector<uint64_t> ciphertext = plaintext;

  for (uint64_t b = 0; b < num_block; b++) {
    block ks = pasta2.keystream(nonce, b);
    for (size_t i = b * params.plain_size;
         i < (b + 1) * params.plain_size && i < size; i++)
      ciphertext[i] = (ciphertext[i] + ks[i - b * params.plain_size]) % modulus;
  }

  return ciphertext;
}

//----------------------------------------------------------------
std::vector<uint64_t> PASTA2::decrypt(std::vector<uint64_t> ciphertext) const {
  uint64_t nonce = 123456789;
  size_t size = ciphertext.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  Pasta2 pasta2(secret_key, instance);
  std::vector<uint64_t> plaintext = ciphertext;

  for (uint64_t b = 0; b < num_block; b++) {
    block ks = pasta2.keystream(nonce, b);
    for (size_t i = b * params.cipher_size;
         i < (b + 1) * params.cipher_size && i < size; i++) {
      if (ks[i - b * params.plain_size] > plaintext[i]) plaintext[i] += modulus;
      plaintext[i] = plaintext[i] - ks[i - b * params.plain_size];
    }
  }

  return plaintext;
}

//----------------------------------------------------------------
void PASTA2::prep_one_block() const {
  uint64_t nonce = 123456789;
  Pasta2 pasta2(instance);
  pasta2.preprocess(nonce, 0);
}

//----------------------------------------------------------------
//----------------------------------------------------------------

Pasta2Instance::Pasta2Instance(uint64_t modulus)
    : modulus(modulus), max_prime_size(0) {
  uint64_t p = modulus;
  while (p) {
    max_prime_size++;
    p >>= 1;
  }
  // reduce two: to prevent that x_i + y_i = 0 for MDS
  x_mask = (1ULL << (max_prime_size - R_BITS - 2)) - 1;
  max_prime_size = (1ULL << max_prime_size) - 1;
  y_mask = max_prime_size >> 2;

  gen_instance();
}

//----------------------------------------------------------------
void Pasta2Instance::init_shake(Keccak_HashInstance& shake128) const {
  uint8_t seed[16] = "PASTA2_";
  seed[7] = '0' + (uint8_t)PASTA2_R;
  *((uint64_t*)(seed + 8)) = htobe64(modulus);

  if (SUCCESS != Keccak_HashInitialize_SHAKE128(&shake128))
    throw std::runtime_error("failed to init shake");
  if (SUCCESS != Keccak_HashUpdate(&shake128, seed, sizeof(seed) * 8))
    throw std::runtime_error("SHAKE128 update failed");
  if (SUCCESS != Keccak_HashFinal(&shake128, NULL))
    throw std::runtime_error("SHAKE128 final failed");
}

//----------------------------------------------------------------
uint64_t Pasta2Instance::generate_random_field_element(
    Keccak_HashInstance& shake128, bool allow_zero) const {
  uint8_t random_bytes[sizeof(uint64_t)];
  while (1) {
    if (SUCCESS !=
        Keccak_HashSqueeze(&shake128, random_bytes, sizeof(random_bytes) * 8))
      throw std::runtime_error("SHAKE128 squeeze failed");
    uint64_t ele = be64toh(*((uint64_t*)random_bytes)) & max_prime_size;
    if (!allow_zero && ele == 0) continue;
    if (ele < modulus) return ele;
  }
}

//----------------------------------------------------------------
// construct cauchy matrix:
// get t distinct x_i
// get t distinct y_i
// if for all i, j: x_i + y_i != 0
// then: a_i_j = (x_i + y_j)^-1 is MDS
// construct:
// - sample s+t y_i with floor(log_2(p)) - 1 bits
// - set x_i to be the least significant ceil(log_2(p)) - r_bits - 2 bits of x_i
// - x_i need to be distinct -> y_i also distinct
// - requires sampling of s+t random values of size floor(log_2(p))
std::vector<std::vector<uint64_t>> Pasta2Instance::get_random_mds_matrix(
    Keccak_HashInstance& shake128) const {
  std::vector<std::vector<uint64_t>> mat(PASTA2_T,
                                         std::vector<uint64_t>(PASTA2_T, 0));
  auto y = get_random_yi(shake128);
  auto x = y;
  for (auto& x_i : x) x_i &= x_mask;

  for (auto i = 0ULL; i < PASTA2_T; i++) {
    for (auto j = 0ULL; j < PASTA2_T; j++) {
      // ld(rasta_prime) ~ 60, no uint128_t for addition necessary
      mat[i][j] = mod_inverse((x[i] + y[j]) % modulus);
    }
  }
  return mat;
}

//----------------------------------------------------------------
std::vector<std::vector<uint64_t>> Pasta2Instance::get_random_matrix_pasta(
    Keccak_HashInstance& shake128) const {
  std::vector<std::vector<uint64_t>> mat(PASTA2_T,
                                         std::vector<uint64_t>(PASTA2_T));
  for(auto& m : mat[0]){
    m = generate_random_field_element(shake128, false);
  }
  const auto& first_row = mat[0];
  auto& prev_row = mat[0];
  for (auto i = 1ULL; i < PASTA2_T; i++) {
    for (auto j = 0ULL; j < PASTA2_T; j++){
          uint64_t tmp =
        ((uint128_t)(first_row[j]) * prev_row[PASTA2_T - 1]) % modulus;
        if (j){
          tmp = (tmp + prev_row[j - 1]) % modulus;
        }
        mat[i][j] = tmp;
    }
    prev_row = mat[i];
  }
  return mat;
}

//----------------------------------------------------------------
std::vector<uint64_t> Pasta2Instance::get_random_yi(
    Keccak_HashInstance& shake128) const {
  std::vector<uint64_t> out(PASTA2_T, 0);
  for (auto i = 0ULL; i < PASTA2_T; i++) {
    bool valid = false;
    // get distinct x_i, which also imply distinct y_i
    while (!valid) {
      // random element of size floor(log_2(p))
      uint8_t random_bytes[sizeof(uint64_t)];
      if (SUCCESS !=
          Keccak_HashSqueeze(&shake128, random_bytes, sizeof(random_bytes) * 8))
        throw std::runtime_error("SHAKE128 squeeze failed");
      uint64_t y_i = be64toh(*((uint64_t*)random_bytes)) & y_mask;
      // check distinct x_i
      uint64_t x_i = y_i & x_mask;
      valid = true;
      for (auto j = 0ULL; j < i; j++) {
        if ((out[j] & x_mask) == x_i) {
          valid = false;
          break;
        }
      }
      if (valid) out[i] = y_i;
    }
  }
  return out;
}

//----------------------------------------------------------------
uint64_t Pasta2Instance::mod_inverse(uint64_t val) const {
  if (val == 0) throw(std::runtime_error("0 has no inverse!"));

  int64_t prev_a = 1;
  int64_t a = 0;
  uint64_t mod = modulus;

  while (mod != 0) {
    int64_t q = val / mod;
    int64_t temp = val % mod;
    val = mod;
    mod = temp;

    temp = a;
    a = prev_a - q * a;
    prev_a = temp;
  }

  if (val != 1) throw(std::runtime_error("value has no inverse!"));

  uint64_t res = prev_a;
  if (prev_a < 0) res += modulus;

  return res;
}

//----------------------------------------------------------------
void Pasta2Instance::gen_instance() {
  Keccak_HashInstance shake128;

  init_shake(shake128);

  rc1.reserve(PASTA2_R);
  rc2.reserve(PASTA2_R);

  for (uint16_t i = 0; i < PASTA2_R; i++) {
    std::vector<uint64_t> rc1_(PASTA2_T);
    std::vector<uint64_t> rc2_(PASTA2_T);

    for (uint16_t j = 0; j < PASTA2_T; j++) {
      rc1_[j] = generate_random_field_element(shake128);
    }
    for (uint16_t j = 0; j < PASTA2_T; j++) {
      rc2_[j] = generate_random_field_element(shake128);
    }
    rc1.push_back(std::move(rc1_));
    rc2.push_back(std::move(rc2_));
  }
  matrix = get_random_mds_matrix(shake128);
  matrix_FL = get_random_matrix_pasta(shake128);
  matrix_FR = get_random_matrix_pasta(shake128);
}

//----------------------------------------------------------------
//----------------------------------------------------------------

void Pasta2::init_shake(uint64_t nonce, uint64_t block_counter) {
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

uint64_t Pasta2::generate_random_field_element(bool allow_zero) {
  uint8_t random_bytes[sizeof(uint64_t)];
  while (1) {
    if (SUCCESS !=
        Keccak_HashSqueeze(&shake128_, random_bytes, sizeof(random_bytes) * 8))
      throw std::runtime_error("SHAKE128 squeeze failed");
    uint64_t ele = be64toh(*((uint64_t*)random_bytes)) & max_prime_size;
    if (!allow_zero && ele == 0) continue;
    if (ele < pasta2_p) return ele;
  }
}

//----------------------------------------------------------------
std::vector<std::vector<uint64_t>> Pasta2::get_random_matrixL() {
  std::vector<uint64_t> diag = get_random_vector(false);
  std::vector<std::vector<uint64_t>> mat = instance.matrix_FL;

  for (auto row = 0ULL; row < PASTA2_T; row++) {
    for (auto col = 0ULL; col < PASTA2_T; col++) {
      mat[row][col] = ((uint128_t)(mat[row][col]) * diag[row]) % pasta2_p;
    }
  }
  return mat;
}

//----------------------------------------------------------------
std::vector<std::vector<uint64_t>> Pasta2::get_random_matrixR() {
  std::vector<uint64_t> diag = get_random_vector(false);
  std::vector<std::vector<uint64_t>> mat = instance.matrix_FR;

  for (auto row = 0ULL; row < PASTA2_T; row++) {
    for (auto col = 0ULL; col < PASTA2_T; col++) {
      mat[row][col] = ((uint128_t)(mat[row][col]) * diag[row]) % pasta2_p;
    }
  }
  return mat;
}

//----------------------------------------------------------------

std::vector<uint64_t> Pasta2::get_random_vector(bool allow_zero) {
  std::vector<uint64_t> rc(PASTA2_T, 0);
  for (uint16_t i = 0; i < PASTA2_T; i++) {
    rc[i] = generate_random_field_element(allow_zero);
  }
  return rc;
}

//----------------------------------------------------------------

Pasta2::Pasta2(const std::vector<uint64_t>& key, const Pasta2Instance& instance)
    : instance(instance),
      key_(key),
      max_prime_size(0),
      pasta2_p(instance.modulus) {
  uint64_t p = pasta2_p;
  while (p) {
    max_prime_size++;
    p >>= 1;
  }
  max_prime_size = (1ULL << max_prime_size) - 1;
}

//----------------------------------------------------------------

Pasta2::Pasta2(const Pasta2Instance& instance)
    : instance(instance), max_prime_size(0), pasta2_p(instance.modulus) {
  uint64_t p = pasta2_p;
  while (p) {
    max_prime_size++;
    p >>= 1;
  }
  max_prime_size = (1ULL << max_prime_size) - 1;
}

//----------------------------------------------------------------

block Pasta2::gen_keystream(const uint64_t nonce,
                            const uint64_t block_counter) {
  init_shake(nonce, block_counter);

  // init state
  for (uint16_t i = 0; i < PASTA2_T; i++) {
    state1_[i] = key_[i];
    state2_[i] = key_[PASTA2_T + i];
  }

  // first random affine with mixing afterwards
  random_linear_layer();
  for (uint8_t r = 0; r < PASTA2_R; r++) {
    round(r);
  }
  return state1_;
}

//----------------------------------------------------------------

block Pasta2::keystream(const uint64_t nonce, const uint64_t block_counter) {
  return gen_keystream(nonce, block_counter);
}

//----------------------------------------------------------------

void Pasta2::preprocess(const uint64_t nonce, const uint64_t block_counter) {
  init_shake(nonce, block_counter);
  std::vector<uint64_t> mat1;
  std::vector<uint64_t> mat2;
  std::vector<uint64_t> rc1;
  std::vector<uint64_t> rc2;

  // First random linear layer
  mat1 = get_random_vector(false);  // characterized by random diagonal
  mat2 = get_random_vector(false);  // characterized by random diagonal
  rc1 = get_random_vector();
  rc2 = get_random_vector();
  volatile uint64_t num = 0xDEADBEEFDEADBEEF % pasta2_p;
  for (size_t i = 0; i < PASTA2_T; i++){
    num = ((uint128_t)(num) * mat1[i]) % pasta2_p;
    num = ((uint128_t)(num) * mat2[i]) % pasta2_p;
    num = (num + rc1[i]) % pasta2_p;
  }
  std::cout << "num: " << num << std::endl;
}

//----------------------------------------------------------------

void Pasta2::round(size_t r) {
  if (r == PASTA2_R - 1) {
    sbox_cube(state1_);
    sbox_cube(state2_);
  } else {
    sbox_feistel(state1_);
    sbox_feistel(state2_);
  }
  fixed_linear_layer(r);
}

//----------------------------------------------------------------

void Pasta2::fixed_linear_layer(size_t r) {
  matmul(state1_, instance.matrix);
  matmul(state2_, instance.matrix);
  add_rc(state1_, state2_, r);
  mix();
}

//----------------------------------------------------------------

void Pasta2::random_linear_layer() {
  random_matmul(state1_, instance.matrix_FL);
  random_matmul(state2_, instance.matrix_FR);
  random_add_rc(state1_);
  random_add_rc(state2_);
  mix();
}

//----------------------------------------------------------------

void Pasta2::add_rc(block& state1, block& state2, size_t r) {
  for (uint16_t el = 0; el < PASTA2_T; el++) {
    // ld(rasta_prime) ~ 60, no uint128_t for addition necessary
    state1[el] = (state1[el] + instance.rc1[r][el]) % pasta2_p;
    state2[el] = (state2[el] + instance.rc2[r][el]) % pasta2_p;
  }
}

//----------------------------------------------------------------

void Pasta2::sbox_cube(block& state) {
  for (uint16_t el = 0; el < PASTA2_T; el++) {
    uint64_t square = ((uint128_t)(state[el]) * state[el]) % pasta2_p;
    state[el] = ((uint128_t)(square)*state[el]) % pasta2_p;
  }
}

//----------------------------------------------------------------

void Pasta2::sbox_feistel(block& state) {
  block new_state;
  new_state[0] = state[0];
  for (uint16_t el = 1; el < PASTA2_T; el++) {
    uint64_t square = ((uint128_t)(state[el - 1]) * state[el - 1]) % pasta2_p;
    // ld(rasta_prime) ~ 60, no uint128_t for addition necessary
    new_state[el] = (square + state[el]) % pasta2_p;
  }
  state = new_state;
}

//----------------------------------------------------------------
// (2 1)(state1_)
// (1 2)(state2_)

void Pasta2::mix() {
  // just adding
  for (uint16_t i = 0; i < PASTA2_T; i++) {
    // ld(rasta_prime) ~ 60, no uint128_t for addition necessary
    uint64_t sum = (state1_[i] + state2_[i]);
    state1_[i] = (state1_[i] + sum) % pasta2_p;
    state2_[i] = (state2_[i] + sum) % pasta2_p;
  }
}

//----------------------------------------------------------------
void Pasta2::matmul(block& state, const std::vector<std::vector<uint64_t>>& matrix) {
  block new_state;
  new_state.fill(0);

  for (uint16_t i = 0; i < PASTA2_T; i++) {
    for (uint16_t j = 0; j < PASTA2_T; j++) {
      uint64_t mult =
          ((uint128_t)(matrix[i][j]) * state[j]) % pasta2_p;
      // ld(rasta_prime) ~ 60, no uint128_t for addition necessary
      new_state[i] = (new_state[i] + mult) % pasta2_p;
    }
  }
  state = new_state;
}

//----------------------------------------------------------------
// requires storage of two rows in the matrix
void Pasta2::random_matmul(block& state, const std::vector<std::vector<uint64_t>>& matrix) {
  matmul(state, matrix);
  for (uint16_t el = 0; el < PASTA2_T; el++) {
    state[el] =
        ((uint128_t)(state[el]) * generate_random_field_element(false)) %
        pasta2_p;
  }
}

//----------------------------------------------------------------

void Pasta2::random_add_rc(block& state) {
  for (uint16_t el = 0; el < PASTA2_T; el++) {
    // ld(rasta_prime) ~ 60, no uint128_t for addition necessary
    state[el] = (state[el] + generate_random_field_element()) % pasta2_p;
  }
}

//----------------------------------------------------------------

std::vector<uint64_t> Pasta2::get_rc_vec(size_t vecsize) {
  std::vector<uint64_t> rc(vecsize + PASTA2_T, 0);
  for (uint16_t i = 0; i < PASTA2_T; i++) {
    rc[i] = generate_random_field_element();
  }
  for (uint16_t i = vecsize; i < vecsize + PASTA2_T; i++) {
    rc[i] = generate_random_field_element();
  }
  return rc;
}

}  // namespace AGPASTA2_3
