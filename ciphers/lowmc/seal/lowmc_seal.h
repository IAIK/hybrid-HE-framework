#pragma once

#include "../plain/lowmc_plain.h"  // for LOWMC_256_128_63_14_PARAMS
#include "../../common/SEAL_Cipher.h"

namespace LOWMC {

constexpr bool use_m4ri = true;

class LOWMC_256_128_63_14_SEAL : public SEALCipher {
 public:
  typedef LOWMC_256_128_63_14 Plain;
  LOWMC_256_128_63_14_SEAL(std::vector<uint8_t> secret_key,
                           std::shared_ptr<seal::SEALContext> con)
      : SEALCipher(LOWMC_256_128_63_14_PARAMS, secret_key, con) {}

  virtual ~LOWMC_256_128_63_14_SEAL() = default;

  virtual std::string get_cipher_name() const {
    return "LOWMC-SEAL (n=256,k=128,m=63,r=14,d=128)";
  }
  virtual void encrypt_key();
  virtual std::vector<seal::Ciphertext> HE_decrypt(
      std::vector<uint8_t>& ciphertext, size_t bits);
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<seal::Ciphertext>& ciphertexts);

 private:
  std::vector<seal::Ciphertext> MultiplyWithGF2Matrix(
      const std::vector<keyblock>& matrix,
      const std::vector<seal::Ciphertext>& k);
  void MultiplyWithGF2MatrixAndAdd(const std::vector<keyblock>& matrix,
                                   const std::vector<seal::Ciphertext>& key,
                                   std::vector<seal::Ciphertext>& state);
  void MultiplyWithGF2Matrix(const std::vector<block>& matrix,
                             std::vector<seal::Ciphertext>& state);

  void MultiplyWithGF2MatrixAndAdd(const mzd_t* matrix,
                                   const std::vector<seal::Ciphertext>& key,
                                   std::vector<seal::Ciphertext>& state);
  void MultiplyWithGF2Matrix(const mzd_t* matrix,
                             std::vector<seal::Ciphertext>& state);

  void addConstant(std::vector<seal::Ciphertext>& state, const block& constant);

  void sboxlayer(std::vector<seal::Ciphertext>& state);
  void Sbox(seal::Ciphertext& a, seal::Ciphertext& b, seal::Ciphertext& c);
  void invSbox(seal::Ciphertext& a, seal::Ciphertext& b, seal::Ciphertext& c);
};

}  // namespace LOWMC
