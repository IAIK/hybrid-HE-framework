#pragma once

#include "../../common/TFHE_Cipher.h"
#include "../plain/he_only_z2_plain.h"  // For HE_ONLY_PARAMS_Z2

namespace HE_ONLY {

class HeOnlyTFHE : public TFHECipher {
 public:
  typedef HeOnlyZ2 Plain;
  HeOnlyTFHE(std::vector<uint8_t> secret_key, int seclevel = 128)
      : TFHECipher(HE_ONLY_PARAMS_Z2, secret_key, seclevel) {}

  virtual ~HeOnlyTFHE() = default;

  virtual std::string get_cipher_name() const { return "HE Only TFHE"; }
  virtual void encrypt_key();
  virtual TFHECiphertextVec HE_decrypt(std::vector<uint8_t>& ciphertext,
                                       size_t bits);
  virtual std::vector<uint8_t> decrypt_result(TFHECiphertextVec& ciphertexts);
};

}  // namespace HE_ONLY
