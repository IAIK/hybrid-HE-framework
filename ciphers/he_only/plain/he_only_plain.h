#pragma once

#include <string>
#include <vector>

#include "../../common_Zp/Cipher.h"

namespace HE_ONLY {

constexpr ZpCipherParams HE_ONLY_PARAMS = {1, 1, 1};

class HeOnly : public ZpCipher {
 public:
  HeOnly(std::vector<uint64_t> secret_key, uint64_t modulus)
      : ZpCipher(HE_ONLY_PARAMS, secret_key, modulus) {}

  virtual ~HeOnly() = default;

  virtual std::string get_cipher_name() const { return "HE Only"; }
  virtual std::vector<uint64_t> encrypt(std::vector<uint64_t> plaintext) const;
  virtual std::vector<uint64_t> decrypt(std::vector<uint64_t> ciphertext) const;

  virtual void prep_one_block() const;
};

}  // namespace HE_ONLY
