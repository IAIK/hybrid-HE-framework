#pragma once

#include "../plain/rasta_6_plain.h"  // for RASTA_128_params
#include "../../common/TFHE_Cipher.h"

namespace RASTA_6 {

constexpr bool use_m4ri = true;

class RASTA_128_TFHE : public TFHECipher {
 public:
  typedef RASTA_128 Plain;
  RASTA_128_TFHE(std::vector<uint8_t> secret_key, int seclevel = 128)
      : TFHECipher(RASTA_128_PARAMS, secret_key, seclevel) {}

  virtual ~RASTA_128_TFHE() = default;

  virtual std::string get_cipher_name() const {
    return "RASTA-TFHE (n=351,r=6)";
  }
  virtual void encrypt_key();
  virtual TFHECiphertextVec HE_decrypt(std::vector<uint8_t>& ciphertexts,
                                       size_t bits);
  virtual std::vector<uint8_t> decrypt_result(TFHECiphertextVec& ciphertexts);

 private:
  void MultiplyWithGF2Matrix(const mzd_t* matrix, TFHECiphertextVec& state);
  void MultiplyWithGF2Matrix(const std::vector<block>& matrix,
                             TFHECiphertextVec& state);
  void addConstant(TFHECiphertextVec& state, const block& constant);
  void add(TFHECiphertextVec& state, TFHECiphertextVec& key);

  void sboxlayer(TFHECiphertextVec& state);
};

}  // namespace RASTA_6
