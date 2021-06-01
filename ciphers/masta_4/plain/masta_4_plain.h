#pragma once

#include <array>
#include <string>
#include <vector>

extern "C" {
#include "KeccakHash.h"
}

#include "../../common_Zp/Cipher.h"

namespace MASTA_4 {

constexpr ZpCipherParams MASTA_128_PARAMS = {128, 128, 128};

class MASTA_128 : public ZpCipher {
 public:
  MASTA_128(std::vector<uint64_t> secret_key, uint64_t modulus)
      : ZpCipher(MASTA_128_PARAMS, secret_key, modulus) {}

  virtual ~MASTA_128() = default;

  virtual std::string get_cipher_name() const { return "MASTA (n=128,r=4)"; }
  virtual std::vector<uint64_t> encrypt(std::vector<uint64_t> plaintext) const;
  virtual std::vector<uint64_t> decrypt(std::vector<uint64_t> ciphertext) const;

  virtual void prep_one_block() const;  // to benchmark matrix generation
};

constexpr uint64_t MASTA_R = 4;
typedef std::array<uint64_t, MASTA_128_PARAMS.key_size> block;
constexpr uint64_t MASTA_ALPHA = 3;

class Masta {
 private:
  Keccak_HashInstance shake128_;

  block key_;
  block state_;
  uint64_t max_prime_size;
  uint64_t masta_p;

  uint64_t generate_random_field_element();

  void round();
  void add_rc();
  void sbox();
  void matmul();
  void keyadd();

  void gen_keystream(const uint64_t nonce, const uint64_t block_counter);

 public:
  Masta(const std::vector<uint64_t>& key, uint64_t modulus);
  Masta(uint64_t modulus);
  ~Masta() = default;

  Masta(const Masta&) = delete;
  Masta& operator=(const Masta&) = delete;
  Masta(const Masta&&) = delete;

  block keystream(const uint64_t nonce, const uint64_t block_counter);
  void preprocess(
      const uint64_t nonce,
      const uint64_t block_counter);  // to benchmark matrix generation

  void init_shake(uint64_t nonce, uint64_t block_counter);
  std::vector<uint64_t> get_random_vector();
  std::vector<std::vector<uint64_t>> get_random_matrix();
};

}  // namespace MASTA_4
