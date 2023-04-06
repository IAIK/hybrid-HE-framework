#pragma once

#include "../../common_Zp/SEAL_Cipher.h"
#include "../plain/hera_5_plain.h"  // for HEARA_PARAMS

namespace HERA_5 {

class HERA_SEAL : public SEALZpCipher {
 public:
  typedef HERA Plain;
  HERA_SEAL(std::vector<uint64_t> secret_key,
            std::shared_ptr<seal::SEALContext> con)
      : SEALZpCipher(HERA_PARAMS, secret_key, con) {}

  virtual ~HERA_SEAL() = default;

  virtual std::string get_cipher_name() const { return "HERA-SEAL (n=16,r=5)"; }
  virtual void encrypt_key(bool batch_encoder = false);
  virtual std::vector<seal::Ciphertext> HE_decrypt(
      std::vector<uint64_t>& ciphertext, bool batch_encoder = false);
  virtual std::vector<uint64_t> decrypt_result(
      std::vector<seal::Ciphertext>& ciphertext, bool batch_encoder = false);
  virtual void add_gk_indices();

 private:
  static constexpr uint64_t BSGS_N1 = 4;
  static constexpr uint64_t BSGS_N2 = 4;
  seal::Ciphertext first_ark(std::vector<uint64_t>& rc);
  void ark(seal::Ciphertext& state, std::vector<uint64_t>& rc);
  void sbox_cube(seal::Ciphertext& state);
  void matmul(seal::Ciphertext& state, std::vector<std::vector<uint64_t>>& mat);
};

}  // namespace HERA_5
