#pragma once

#include "../../common_Zp/SEAL_Cipher.h"
#include "../plain/pasta_3_plain.h"  // for PASTA_params

namespace PASTA_3 {

class PASTA_SEAL : public SEALZpCipher {
 public:
  typedef PASTA Plain;
  PASTA_SEAL(std::vector<uint64_t> secret_key,
             std::shared_ptr<seal::SEALContext> con)
      : SEALZpCipher(PASTA_PARAMS, secret_key, con),
        slots(this->batch_encoder.slot_count()),
        halfslots(slots >> 1) {}

  virtual ~PASTA_SEAL() = default;

  virtual std::string get_cipher_name() const {
    return "PASTA-SEAL (n=128,r=3)";
  }
  virtual void encrypt_key(bool batch_encoder = false);
  virtual std::vector<seal::Ciphertext> HE_decrypt(
      std::vector<uint64_t>& ciphertext, bool batch_encoder = false);
  virtual std::vector<uint64_t> decrypt_result(
      std::vector<seal::Ciphertext>& ciphertext, bool batch_encoder = false);
  virtual void add_gk_indices();

 private:
  static constexpr bool REMOVE_SECOND_VEC = false;
  static constexpr uint64_t BSGS_N1 = 16;
  static constexpr uint64_t BSGS_N2 = 8;
  size_t slots;
  size_t halfslots;

  void sbox_feistel(seal::Ciphertext& state);
  void sbox_cube(seal::Ciphertext& state);
  void matmul(seal::Ciphertext& state,
              const std::vector<std::vector<uint64_t>>& mat1,
              const std::vector<std::vector<uint64_t>>& mat2);
  void add_rc(seal::Ciphertext& state, const std::vector<uint64_t>& rc);
  void mix(seal::Ciphertext& state);

  void diagonal(seal::Ciphertext& state,
                const std::vector<std::vector<uint64_t>>& mat1,
                const std::vector<std::vector<uint64_t>>& mat2);
  void babystep_giantstep(seal::Ciphertext& state,
                          const std::vector<std::vector<uint64_t>>& mat1,
                          const std::vector<std::vector<uint64_t>>& mat2);
};

}  // namespace PASTA_3
