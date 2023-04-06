#pragma once

#include <array>
#include <string>
#include <vector>

extern "C" {
#include "KeccakHash.h"
}

#include "../../common_Zp/Cipher.h"

namespace HERA_5 {

constexpr ZpCipherParams HERA_PARAMS = {16, 16, 16};

class HERA : public ZpCipher {
 public:
  HERA(std::vector<uint64_t> secret_key, uint64_t modulus)
      : ZpCipher(HERA_PARAMS, secret_key, modulus) {}

  virtual ~HERA() = default;

  virtual std::string get_cipher_name() const { return "HERA (n=16,r=5)"; }
  virtual std::vector<uint64_t> encrypt(std::vector<uint64_t> plaintext) const;
  virtual std::vector<uint64_t> decrypt(std::vector<uint64_t> ciphertext) const;

  virtual void prep_one_block() const;  // to benchmark matrix generation
};

constexpr uint64_t HERA_R = 5;
typedef std::array<uint64_t, HERA_PARAMS.key_size> block;

class Hera {
 private:
  Keccak_HashInstance shake128_;

  block key_;
  block state_;
  uint64_t max_prime_size;
  uint64_t hera_p;

  uint64_t generate_random_field_element();

  void round();
  void final_round();
  void ark();
  void sbox_cube();
  void matmul();
  void mix_columns();
  void mix_rows();

  void gen_keystream(const uint64_t nonce, const uint64_t block_counter);

 public:
  Hera(const std::vector<uint64_t>& key, uint64_t modulus);
  Hera(uint64_t modulus);
  ~Hera() = default;

  Hera(const Hera&) = delete;
  Hera& operator=(const Hera&) = delete;
  Hera(const Hera&&) = delete;

  std::vector<std::vector<uint64_t>> matrix = {
      {4, 6, 2, 2, 6, 9, 3, 3, 2, 3, 1, 1, 2, 3, 1, 1},
      {2, 4, 6, 2, 3, 6, 9, 3, 1, 2, 3, 1, 1, 2, 3, 1},
      {2, 2, 4, 6, 3, 3, 6, 9, 1, 1, 2, 3, 1, 1, 2, 3},
      {6, 2, 2, 4, 9, 3, 3, 6, 3, 1, 1, 2, 3, 1, 1, 2},
      {2, 3, 1, 1, 4, 6, 2, 2, 6, 9, 3, 3, 2, 3, 1, 1},
      {1, 2, 3, 1, 2, 4, 6, 2, 3, 6, 9, 3, 1, 2, 3, 1},
      {1, 1, 2, 3, 2, 2, 4, 6, 3, 3, 6, 9, 1, 1, 2, 3},
      {3, 1, 1, 2, 6, 2, 2, 4, 9, 3, 3, 6, 3, 1, 1, 2},
      {2, 3, 1, 1, 2, 3, 1, 1, 4, 6, 2, 2, 6, 9, 3, 3},
      {1, 2, 3, 1, 1, 2, 3, 1, 2, 4, 6, 2, 3, 6, 9, 3},
      {1, 1, 2, 3, 1, 1, 2, 3, 2, 2, 4, 6, 3, 3, 6, 9},
      {3, 1, 1, 2, 3, 1, 1, 2, 6, 2, 2, 4, 9, 3, 3, 6},
      {6, 9, 3, 3, 2, 3, 1, 1, 2, 3, 1, 1, 4, 6, 2, 2},
      {3, 6, 9, 3, 1, 2, 3, 1, 1, 2, 3, 1, 2, 4, 6, 2},
      {3, 3, 6, 9, 1, 1, 2, 3, 1, 1, 2, 3, 2, 2, 4, 6},
      {9, 3, 3, 6, 3, 1, 1, 2, 3, 1, 1, 2, 6, 2, 2, 4}};

  block keystream(const uint64_t nonce, const uint64_t block_counter);
  void preprocess(
      const uint64_t nonce,
      const uint64_t block_counter);  // to benchmark matrix generation

  void init_shake(uint64_t nonce, uint64_t block_counter);
  std::vector<uint64_t> get_random_vector();
};

}  // namespace HERA_5
