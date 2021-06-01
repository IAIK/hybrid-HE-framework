#pragma once

// an abstract interface of an Z_p cipher, for plain evaluation

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

struct ZpCipherParams {
  size_t key_size;
  size_t plain_size;
  size_t cipher_size;
};

class ZpCipher {
 protected:
  std::vector<uint64_t> secret_key;
  ZpCipherParams params;
  uint64_t modulus;

 public:
  ZpCipher(ZpCipherParams params, std::vector<uint64_t> secret_key,
           uint64_t modulus)
      : secret_key(secret_key), params(params), modulus(modulus) {
    if (secret_key.size() != params.key_size)
      throw std::runtime_error("Invalid Key length");
  }
  virtual ~ZpCipher() = default;
  // Size of the secret key in words
  size_t get_key_size() const { return params.key_size; }
  // Size of a plaintext block in words
  size_t get_plain_size() const { return params.plain_size; }
  // Size of a plaintext block in words
  size_t get_cipher_size() const { return params.cipher_size; }

  // A displayable name for this cipher
  virtual std::string get_cipher_name() const = 0;

  virtual std::vector<uint64_t> encrypt(
      std::vector<uint64_t> plaintext) const = 0;
  virtual std::vector<uint64_t> decrypt(
      std::vector<uint64_t> ciphertext) const = 0;

  virtual void prep_one_block() const = 0;
};
