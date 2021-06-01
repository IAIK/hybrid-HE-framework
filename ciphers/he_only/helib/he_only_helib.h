#pragma once

#include "../../common_Zp/HElib_Cipher.h"
#include "../plain/he_only_plain.h"  // for HE_ONLY_PARAMS

namespace HE_ONLY {

class HeOnlyHElib : public HElibZpCipher {
 public:
  typedef HeOnly Plain;
  HeOnlyHElib(std::vector<uint64_t> secret_key,
              std::shared_ptr<helib::Context> con, long L, long c)
      : HElibZpCipher(HE_ONLY_PARAMS, secret_key, con, L, c, true) {}

  virtual ~HeOnlyHElib() = default;

  virtual std::string get_cipher_name() const { return "HE Only HElib"; }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(
      std::vector<uint64_t>& ciphertext);
  virtual std::vector<uint64_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertext);
  virtual void add_gk_indices();
};

}  // namespace HE_ONLY
