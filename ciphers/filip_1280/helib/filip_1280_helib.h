#pragma once

#include "../plain/filip_1280_plain.h"  // for FILIP_1280_PARAMS
#include "../../common/HElib_Cipher.h"

namespace FILIP_1280 {

class FiLIP_1280_HElib : public HElibCipher {
 public:
  typedef FiLIP_1280 Plain;
  FiLIP_1280_HElib(std::vector<uint8_t> secret_key,
                   std::shared_ptr<helib::Context> con, long L, long c)
      : HElibCipher(FILIP_1280_PARAMS, secret_key, con, L, c) {}

  virtual ~FiLIP_1280_HElib() = default;

  virtual std::string get_cipher_name() const { return "FiLIP-1280-HElib"; }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(std::vector<uint8_t>& ciphertext,
                                              size_t bits);
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertexts);

 private:
  void FLIP(std::vector<helib::Ctxt>& state, helib::Ctxt& out);
  void treeMul(std::vector<helib::Ctxt>& tree);
};

}  // namespace FILIP_1280
