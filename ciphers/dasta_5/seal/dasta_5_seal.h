#pragma once

#include "../plain/dasta_5_plain.h"  // for DASTA_128_params
#include "../../common/SEAL_Cipher.h"

namespace DASTA_5 {

constexpr bool use_m4ri = true;

class DASTA_128_SEAL : public SEALCipher {
 public:
  typedef DASTA_128 Plain;
  DASTA_128_SEAL(std::vector<uint8_t> secret_key,
                 std::shared_ptr<seal::SEALContext> con)
      : SEALCipher(DASTA_128_PARAMS, secret_key, con) {}

  virtual ~DASTA_128_SEAL() = default;

  virtual std::string get_cipher_name() const {
    return "DASTA-SEAL (n=525,r=5)";
  }
  virtual void encrypt_key();
  virtual std::vector<seal::Ciphertext> HE_decrypt(
      std::vector<uint8_t>& ciphertext, size_t bits);
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<seal::Ciphertext>& ciphertexts);

 private:
  void MultiplyWithGF2Matrix(const mzd_t* matrix,
                             std::vector<seal::Ciphertext>& state);
  void MultiplyPermutedWithGF2Matrix(
      const std::array<block, blocksize>& matrix,
      const std::array<uint16_t, blocksize>& perm,
      std::vector<seal::Ciphertext>& state);
  void add(std::vector<seal::Ciphertext>& state,
           const std::vector<seal::Ciphertext>& key);

  void sboxlayer(std::vector<seal::Ciphertext>& state);
};

}  // namespace DASTA_5
