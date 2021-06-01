#pragma once

#include "../plain/dasta_6_plain.h"  // for DASTA_128_params
#include "../../common/TFHE_Cipher.h"

namespace DASTA_6 {

constexpr bool use_m4ri = true;

class DASTA_128_TFHE : public TFHECipher {
 public:
  typedef DASTA_128 Plain;
  DASTA_128_TFHE(std::vector<uint8_t> secret_key, int seclevel = 128)
      : TFHECipher(DASTA_128_PARAMS, secret_key, seclevel) {}

  virtual ~DASTA_128_TFHE() = default;

  virtual std::string get_cipher_name() const {
    return "DASTA-TFHE (n=351,r=6)";
  }
  virtual void encrypt_key();
  virtual TFHECiphertextVec HE_decrypt(std::vector<uint8_t>& ciphertexts,
                                       size_t bits);
  virtual std::vector<uint8_t> decrypt_result(TFHECiphertextVec& ciphertexts);

 private:
  void MultiplyWithGF2Matrix(const mzd_t* matrix, TFHECiphertextVec& state);
  void MultiplyPermutedWithGF2Matrix(
      const std::array<block, blocksize>& matrix,
      const std::array<uint16_t, blocksize>& perm, TFHECiphertextVec& state);
  void add(TFHECiphertextVec& state, TFHECiphertextVec& key);

  void sboxlayer(TFHECiphertextVec& state);
};

}  // namespace DASTA_6
