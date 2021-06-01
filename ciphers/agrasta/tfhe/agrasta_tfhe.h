#pragma once

#include "../plain/agrasta_plain.h"  // for AGRASTA_128_params
#include "../../common/TFHE_Cipher.h"

namespace AGRASTA {

constexpr bool use_m4ri = true;

class AGRASTA_128_TFHE : public TFHECipher {
 public:
  typedef AGRASTA_128 Plain;
  AGRASTA_128_TFHE(std::vector<uint8_t> secret_key, int seclevel = 128)
      : TFHECipher(AGRASTA_128_PARAMS, secret_key, seclevel) {}

  virtual ~AGRASTA_128_TFHE() = default;

  virtual std::string get_cipher_name() const {
    return "AGRASTA-TFHE (n=129,r=4)";
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

}  // namespace AGRASTA
