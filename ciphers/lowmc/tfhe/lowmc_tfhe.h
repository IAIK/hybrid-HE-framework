#pragma once

#include "../plain/lowmc_plain.h"  // for LOWMC_256_128_63_14_PARAMS
#include "../../common/TFHE_Cipher.h"

namespace LOWMC {

constexpr bool use_m4ri = true;

class LOWMC_256_128_63_14_TFHE : public TFHECipher {
 public:
  typedef LOWMC_256_128_63_14 Plain;
  LOWMC_256_128_63_14_TFHE(std::vector<uint8_t> secret_key, int seclevel = 128)
      : TFHECipher(LOWMC_256_128_63_14_PARAMS, secret_key, seclevel) {}

  virtual ~LOWMC_256_128_63_14_TFHE() = default;

  virtual std::string get_cipher_name() const {
    return "LOWMC-TFHE(n=256,k=128,m=63,r=14,d=128)";
  }
  virtual void encrypt_key();
  virtual TFHECiphertextVec HE_decrypt(std::vector<uint8_t>& ciphertext,
                                       size_t bits);
  virtual std::vector<uint8_t> decrypt_result(TFHECiphertextVec& ciphertexts);

 private:
  TFHECiphertextVec MultiplyWithGF2Matrix(const std::vector<keyblock>& matrix,
                                          const TFHECiphertextVec& k);
  void MultiplyWithGF2MatrixAndAdd(const std::vector<keyblock>& matrix,
                                   const TFHECiphertextVec& key,
                                   TFHECiphertextVec& state);
  void MultiplyWithGF2Matrix(const std::vector<block>& matrix,
                             TFHECiphertextVec& state);

  void MultiplyWithGF2MatrixAndAdd(const mzd_t* matrix,
                                   const TFHECiphertextVec& key,
                                   TFHECiphertextVec& state);
  void MultiplyWithGF2Matrix(const mzd_t* matrix, TFHECiphertextVec& state);

  void addConstant(TFHECiphertextVec& state, const block& constant);

  void sboxlayer(TFHECiphertextVec& state);
  void Sbox(LweSample& a, LweSample& b, LweSample& c);
  void invSbox(LweSample& a, LweSample& b, LweSample& c);
};

}  // namespace LOWMC
