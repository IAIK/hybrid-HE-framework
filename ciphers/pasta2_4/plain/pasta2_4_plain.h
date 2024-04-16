#pragma once

#include <array>
#include <string>
#include <vector>
#include <iostream>

extern "C" {
#include "KeccakHash.h"
}

#include "../../common_Zp/Cipher.h"

namespace PASTA2_4 {

//----------------------------------------------------------------
constexpr ZpCipherParams PASTA2_PARAMS = {64, 32, 32};
constexpr uint64_t PASTA2_T = PASTA2_PARAMS.plain_size;
constexpr uint64_t PASTA2_R = 4;
constexpr uint64_t R_BITS = 7;  // for MDS Matrix

//----------------------------------------------------------------
class Pasta2Instance {
 private:
  uint64_t max_prime_size;
  uint64_t x_mask;
  uint64_t y_mask;

  void init_shake(Keccak_HashInstance&) const;
  uint64_t generate_random_field_element(Keccak_HashInstance&,
                                         bool allow_zero = true) const;
  std::vector<std::vector<uint64_t>> get_random_mds_matrix(
      Keccak_HashInstance&) const;
  std::vector<std::vector<uint64_t>> get_random_matrix_pasta(
    Keccak_HashInstance& shake128) const;
  std::vector<uint64_t> get_random_yi(Keccak_HashInstance&) const;
  uint64_t mod_inverse(uint64_t val) const;

 public:
  uint64_t modulus;

  std::vector<std::vector<uint64_t>> matrix;
  std::vector<std::vector<uint64_t>> matrix_FR;
  std::vector<std::vector<uint64_t>> matrix_FL;
  std::vector<std::vector<uint64_t>> rc1;
  std::vector<std::vector<uint64_t>> rc2;

  Pasta2Instance(uint64_t modulus);
  ~Pasta2Instance() = default;

  Pasta2Instance(const Pasta2Instance&) = delete;
  Pasta2Instance& operator=(const Pasta2Instance&) = delete;
  Pasta2Instance(const Pasta2Instance&&) = delete;

  void gen_instance();
};

//----------------------------------------------------------------

class PASTA2 : public ZpCipher {
 private:
  Pasta2Instance instance;

 public:
  PASTA2(std::vector<uint64_t> secret_key, uint64_t modulus);

  virtual ~PASTA2() = default;

  virtual std::string get_cipher_name() const { return "PASTA2 (n=32,r=4)"; }
  virtual std::vector<uint64_t> encrypt(std::vector<uint64_t> plaintext) const;
  virtual std::vector<uint64_t> decrypt(std::vector<uint64_t> ciphertext) const;

  virtual void prep_one_block() const;  // to benchmark random generation
};

//----------------------------------------------------------------
typedef std::vector<uint64_t> key_block;
typedef std::array<uint64_t, PASTA2_T> block;

class Pasta2 {
 private:
  Keccak_HashInstance shake128_;

  const Pasta2Instance& instance;

  key_block key_;
  block state1_;
  block state2_;

  uint64_t max_prime_size;
  uint64_t pasta2_p;

  std::vector<uint64_t> calculate_row(const std::vector<uint64_t>& prev_row,
                                      const std::vector<uint64_t>& first_row);
  uint64_t generate_random_field_element(bool allow_zero = true);

  void round(size_t r);
  void sbox_cube(block& state);
  void sbox_feistel(block& state);
  void fixed_linear_layer(size_t r);
  void random_linear_layer();
  void matmul(block& state, const std::vector<std::vector<uint64_t>>& matrix);
  void add_rc(block& state1, block& state2, size_t r);
  void random_matmul(block& state, const std::vector<std::vector<uint64_t>>& matrix);
  void random_add_rc(block& state);
  void mix();

  block gen_keystream(const uint64_t nonce, const uint64_t block_counter);

 public:
  Pasta2(const std::vector<uint64_t>& key, const Pasta2Instance&);
  Pasta2(const Pasta2Instance&);
  ~Pasta2() = default;

  Pasta2(const Pasta2&) = delete;
  Pasta2& operator=(const Pasta2&) = delete;
  Pasta2(const Pasta2&&) = delete;

  block keystream(const uint64_t nonce, const uint64_t block_counter);
  void preprocess(
      const uint64_t nonce,
      const uint64_t block_counter);  // to benchmark random generation

  void init_shake(uint64_t nonce, uint64_t block_counter);
  std::vector<uint64_t> get_random_vector(bool allow_zero = true);
  std::vector<std::vector<uint64_t>> get_random_matrixL();
  std::vector<std::vector<uint64_t>> get_random_matrixR();

  std::vector<uint64_t> get_rc_vec(size_t vecsize);
};

}  // namespace PASTA2_4
