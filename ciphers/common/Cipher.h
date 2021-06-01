#pragma once

// an abstract interface of a cipher, for plain evaluation

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

struct BlockCipherParams {
  size_t key_size_bytes;
  size_t key_size_bits;
  size_t plain_size_bytes;
  size_t plain_size_bits;
  size_t cipher_size_bytes;
  size_t cipher_size_bits;
};

class BlockCipher {
 protected:
  std::vector<uint8_t> secret_key;
  BlockCipherParams params;

 public:
  BlockCipher(BlockCipherParams params, std::vector<uint8_t> secret_key)
      : secret_key(secret_key), params(params) {
    if (secret_key.size() != params.key_size_bytes)
      throw std::runtime_error("Invalid Key length");
  }
  virtual ~BlockCipher() = default;
  // Size of the secret key in bytes
  size_t get_key_size_bytes() const { return params.key_size_bytes; }
  // Size of the secret key in bits
  size_t get_key_size_bits() const { return params.key_size_bits; }
  // Size of a plaintext block in bytes
  size_t get_plain_size_bytes() const { return params.plain_size_bytes; }
  // Size of a plaintext block in bits
  size_t get_plain_size_bits() const { return params.plain_size_bits; }
  // Size of a plaintext block in bytes
  size_t get_cipher_size_bytes() const { return params.cipher_size_bytes; }
  // Size of a plaintext block in bits
  size_t get_cipher_size_bits() const { return params.cipher_size_bits; }

  // A displayable name for this cipher
  virtual std::string get_cipher_name() const = 0;

  virtual std::vector<uint8_t> encrypt(std::vector<uint8_t> plaintext,
                                       size_t bits) const = 0;
  virtual std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext,
                                       size_t bits) const = 0;

  virtual void prep_one_block() const = 0;
};
