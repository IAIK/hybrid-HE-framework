#pragma once

#include "../../common_Zp/SEAL_Cipher.h"
#include "../plain/masta_4_plain.h"  // for MASTA_128_params

namespace MASTA_4 {

class MASTA_128_SEAL : public SEALZpCipher {
 public:
  typedef MASTA_128 Plain;
  MASTA_128_SEAL(std::vector<uint64_t> secret_key,
                 std::shared_ptr<seal::SEALContext> con)
      : SEALZpCipher(MASTA_128_PARAMS, secret_key, con) {}

  virtual ~MASTA_128_SEAL() = default;

  virtual std::string get_cipher_name() const {
    return "MASTA-SEAL (n=128,r=4)";
  }
  virtual void encrypt_key(bool batch_encoder = false);
  virtual std::vector<seal::Ciphertext> HE_decrypt(
      std::vector<uint64_t>& ciphertext, bool batch_encoder = false);
  virtual std::vector<uint64_t> decrypt_result(
      std::vector<seal::Ciphertext>& ciphertext, bool batch_encoder = false);
  virtual void add_gk_indices();

 private:
  static constexpr uint64_t BSGS_N1 = 16;
  static constexpr uint64_t BSGS_N2 = 8;

  void add_rc(seal::Ciphertext& state, std::vector<uint64_t>& rc);
  void sbox(seal::Ciphertext& state);
  void matmul(seal::Ciphertext& state, std::vector<std::vector<uint64_t>>& mat);
};

}  // namespace MASTA_4
