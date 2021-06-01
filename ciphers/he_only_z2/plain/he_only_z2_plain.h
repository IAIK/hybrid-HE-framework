#pragma once

#include <string>
#include <vector>

#include "../../common/Cipher.h"

namespace HE_ONLY {

constexpr BlockCipherParams HE_ONLY_PARAMS_Z2 = {1, 1, 1, 1, 1, 1};

class HeOnlyZ2 : public BlockCipher {
 public:
  HeOnlyZ2(std::vector<uint8_t> secret_key)
      : BlockCipher(HE_ONLY_PARAMS_Z2, secret_key) {}

  virtual ~HeOnlyZ2() = default;

  virtual std::string get_cipher_name() const { return "HE Only Z2"; }
  virtual std::vector<uint8_t> encrypt(std::vector<uint8_t> plaintext,
                                       size_t bits) const;
  virtual std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext,
                                       size_t bits) const;

  virtual void prep_one_block() const;
};

}  // namespace HE_ONLY
