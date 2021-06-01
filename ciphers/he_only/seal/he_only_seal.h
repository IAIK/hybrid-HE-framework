#pragma once

#include "../../common_Zp/SEAL_Cipher.h"
#include "../plain/he_only_plain.h"  // for HE_ONLY_PARAMS

namespace HE_ONLY {

class HeOnlySEAL : public SEALZpCipher {
 public:
  typedef HeOnly Plain;
  HeOnlySEAL(std::vector<uint64_t> secret_key,
             std::shared_ptr<seal::SEALContext> con)
      : SEALZpCipher(HE_ONLY_PARAMS, secret_key, con) {}

  virtual ~HeOnlySEAL() = default;

  virtual std::string get_cipher_name() const { return "HE Only SEAL"; }
  virtual void encrypt_key(bool batch_encoder = false);
  virtual std::vector<seal::Ciphertext> HE_decrypt(
      std::vector<uint64_t>& ciphertext, bool batch_encoder = false);
  virtual std::vector<uint64_t> decrypt_result(
      std::vector<seal::Ciphertext>& ciphertext, bool batch_encoder = false);
  virtual void add_gk_indices();
};

}  // namespace HE_ONLY
