#pragma once

#include <array>
#include <string>
#include <vector>

extern "C" {
#include "KeccakHash.h"
}

#include "../../common_Zp/Cipher.h"

namespace PASTA_3 {

constexpr ZpCipherParams PASTA_PARAMS = {256, 128, 128};

class PASTA : public ZpCipher {
 public:
  PASTA(std::vector<uint64_t> secret_key, uint64_t modulus)
      : ZpCipher(PASTA_PARAMS, secret_key, modulus) {}

  virtual ~PASTA() = default;

  virtual std::string get_cipher_name() const { return "PASTA (n=128,r=3)"; }
  virtual std::vector<uint64_t> encrypt(std::vector<uint64_t> plaintext) const;
  virtual std::vector<uint64_t> decrypt(std::vector<uint64_t> ciphertext) const;

  virtual void prep_one_block() const;  // to benchmark matrix generation
};

constexpr uint64_t PASTA_T = PASTA_PARAMS.plain_size;
constexpr uint64_t PASTA_R = 3;

typedef std::vector<uint64_t> key_block;
typedef std::array<uint64_t, PASTA_T> block;

class Pasta {
 private:
  Keccak_HashInstance shake128_;

  key_block key_;
  block state1_;
  block state2_;

  uint64_t max_prime_size;
  uint64_t pasta_p;

  std::vector<uint64_t> calculate_row(const std::vector<uint64_t>& prev_row,
                                      const std::vector<uint64_t>& first_row);
  uint64_t generate_random_field_element(bool allow_zero = true);

  void round(size_t r);
  void sbox_cube(block& state);
  void sbox_feistel(block& state);
  void linear_layer();
  void matmul(block& state);
  void add_rc(block& state);
  void mix();

  block gen_keystream(const uint64_t nonce, const uint64_t block_counter);

 public:
  Pasta(const std::vector<uint64_t>& key, uint64_t modulus);
  Pasta(uint64_t modulus);
  ~Pasta() = default;

  Pasta(const Pasta&) = delete;
  Pasta& operator=(const Pasta&) = delete;
  Pasta(const Pasta&&) = delete;

  block keystream(const uint64_t nonce, const uint64_t block_counter);
  void preprocess(
      const uint64_t nonce,
      const uint64_t block_counter);  // to benchmark matrix generation

  void init_shake(uint64_t nonce, uint64_t block_counter);
  std::vector<uint64_t> get_random_vector(bool allow_zero = true);
  std::vector<std::vector<uint64_t>> get_random_matrix();

  std::vector<uint64_t> get_rc_vec(size_t vecsize);
};

}  // namespace PASTA_3
