#pragma once

#include "../plain/agrasta_plain.h"  // for AGRASTA_128_params
#include "../../common/SEAL_Cipher.h"

namespace AGRASTA {

constexpr bool use_m4ri = true;

class AGRASTA_128_SEAL : public SEALCipher {
 public:
  typedef AGRASTA_128 Plain;
  AGRASTA_128_SEAL(std::vector<uint8_t> secret_key,
                   std::shared_ptr<seal::SEALContext> con)
      : SEALCipher(AGRASTA_128_PARAMS, secret_key, con) {}

  virtual ~AGRASTA_128_SEAL() = default;

  virtual std::string get_cipher_name() const {
    return "AGRASTA-SEAL (n=129,r=4)";
  }
  virtual void encrypt_key();
  virtual std::vector<seal::Ciphertext> HE_decrypt(
      std::vector<uint8_t>& ciphertext, size_t bits);
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<seal::Ciphertext>& ciphertexts);

 private:
  void MultiplyWithGF2Matrix(const mzd_t* matrix,
                             std::vector<seal::Ciphertext>& state);
  void MultiplyWithGF2Matrix(const std::vector<block>& matrix,
                             std::vector<seal::Ciphertext>& state);
  void addConstant(std::vector<seal::Ciphertext>& state, const block& constant);
  void add(std::vector<seal::Ciphertext>& state,
           const std::vector<seal::Ciphertext>& key);

  void sboxlayer(std::vector<seal::Ciphertext>& state);
};

}  // namespace AGRASTA
