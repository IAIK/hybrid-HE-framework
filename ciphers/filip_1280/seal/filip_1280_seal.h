#pragma once

#include "../plain/filip_1280_plain.h"  // for FILIP_1280_PARAMS
#include "../../common/SEAL_Cipher.h"

namespace FILIP_1280 {

class FiLIP_1280_SEAL : public SEALCipher {
 public:
  typedef FiLIP_1280 Plain;
  FiLIP_1280_SEAL(std::vector<uint8_t> secret_key,
                  std::shared_ptr<seal::SEALContext> con)
      : SEALCipher(FILIP_1280_PARAMS, secret_key, con) {}

  virtual ~FiLIP_1280_SEAL() = default;

  virtual std::string get_cipher_name() const { return "FiLIP-1280-SEAL"; }
  virtual void encrypt_key();
  virtual std::vector<seal::Ciphertext> HE_decrypt(
      std::vector<uint8_t>& ciphertext, size_t bits);
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<seal::Ciphertext>& ciphertexts);

 private:
  void FLIP(std::vector<seal::Ciphertext>& state, seal::Ciphertext& out);
  void treeMul(std::vector<seal::Ciphertext>& tree);
};

}  // namespace FILIP_1280
