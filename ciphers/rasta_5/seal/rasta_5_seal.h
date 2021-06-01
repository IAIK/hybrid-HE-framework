#pragma once

#include "../plain/rasta_5_plain.h"  // for RASTA_128_params
#include "../../common/SEAL_Cipher.h"

namespace RASTA_5 {

constexpr bool use_m4ri = true;

class RASTA_128_SEAL : public SEALCipher {
 public:
  typedef RASTA_128 Plain;
  RASTA_128_SEAL(std::vector<uint8_t> secret_key,
                 std::shared_ptr<seal::SEALContext> con)
      : SEALCipher(RASTA_128_PARAMS, secret_key, con) {}

  virtual ~RASTA_128_SEAL() = default;

  virtual std::string get_cipher_name() const {
    return "RASTA-SEAL (n=525,r=5)";
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

}  // namespace RASTA_5
