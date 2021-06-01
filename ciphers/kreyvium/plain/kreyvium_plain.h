#pragma once

#include <bitset>
#include <string>
#include <vector>

#include "../../common/Cipher.h"

namespace KREYVIUM {

// Blockcipher just for testing a plaintext/ciphertext with specific size
constexpr BlockCipherParams KREYVIUM_PARAMS = {16, 128, 6, 46, 6, 46};

constexpr unsigned STATE_SIZE = 288;
constexpr unsigned IV_SIZE = KREYVIUM_PARAMS.key_size_bits;

typedef std::bitset<STATE_SIZE> stateblock;
typedef std::bitset<IV_SIZE> ivblock;
typedef std::bitset<KREYVIUM_PARAMS.key_size_bits> keyblock;

class Kreyvium : public BlockCipher {
 public:
  Kreyvium(std::vector<uint8_t> secret_key)
      : BlockCipher(KREYVIUM_PARAMS, secret_key) {}

  virtual ~Kreyvium() = default;

  virtual std::string get_cipher_name() const { return "KREYVIUM"; }
  virtual std::vector<uint8_t> encrypt(std::vector<uint8_t> plaintext,
                                       size_t bits) const;
  virtual std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext,
                                       size_t bits) const;

  virtual void prep_one_block() const;

 private:
  std::vector<uint8_t> keystream(const keyblock& key, const ivblock& iv,
                                 size_t bits) const;
  void init(const keyblock& key, const ivblock& iv, stateblock& state,
            ivblock& inner_iv, keyblock& inner_key) const;
};

}  // namespace KREYVIUM
