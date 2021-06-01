#pragma once

#include "../plain/filip_1280_plain.h"  // for FILIP_1280_PARAMS
#include "../../common/TFHE_Cipher.h"

namespace FILIP_1280 {

class FiLIP_1280_TFHE : public TFHECipher {
 public:
  typedef FiLIP_1280 Plain;
  FiLIP_1280_TFHE(std::vector<uint8_t> secret_key, int seclevel = 128)
      : TFHECipher(FILIP_1280_PARAMS, secret_key, seclevel) {}

  virtual ~FiLIP_1280_TFHE() = default;

  virtual std::string get_cipher_name() const { return "FiLIP-1280-TFHE"; }
  virtual void encrypt_key();
  virtual TFHECiphertextVec HE_decrypt(std::vector<uint8_t>& ciphertext,
                                       size_t bits);
  virtual std::vector<uint8_t> decrypt_result(TFHECiphertextVec& ciphertexts);

 private:
  void FLIP(TFHECiphertextVec& state, LweSample& out);
};

}  // namespace FILIP_1280
