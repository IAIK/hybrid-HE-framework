#pragma once

#include "../../common_Zp/HElib_Cipher.h"
#include "../plain/pasta_4_plain.h"  // for PASTA_params

namespace PASTA_4 {

class PASTA_HElib : public HElibZpCipher {
 public:
  typedef PASTA Plain;
  PASTA_HElib(std::vector<uint64_t> secret_key,
              std::shared_ptr<helib::Context> con, long L, long c)
      : HElibZpCipher(PASTA_PARAMS, secret_key, con, L, c, true),
        halfslots(nslots >> 1) {}

  virtual ~PASTA_HElib() = default;

  virtual std::string get_cipher_name() const {
    return "PASTA-HElib (n=32,r=4)";
  }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(
      std::vector<uint64_t>& ciphertext);
  virtual std::vector<uint64_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertext);
  virtual void add_gk_indices();

 private:
  static constexpr bool REMOVE_SECOND_VEC = false;
  static constexpr uint64_t BSGS_N1 = 8;
  static constexpr uint64_t BSGS_N2 = 4;
  size_t halfslots;

  void sbox_feistel(helib::Ctxt& state);
  void sbox_cube(helib::Ctxt& state);
  void matmul(helib::Ctxt& state,
              const std::vector<std::vector<uint64_t>>& mat1,
              const std::vector<std::vector<uint64_t>>& mat2);
  void add_rc(helib::Ctxt& state, std::vector<uint64_t>& rc);
  void mix(helib::Ctxt& state);

  void diagonal(helib::Ctxt& state,
                const std::vector<std::vector<uint64_t>>& mat1,
                const std::vector<std::vector<uint64_t>>& mat2);
  void babystep_giantstep(helib::Ctxt& state,
                          const std::vector<std::vector<uint64_t>>& mat1,
                          const std::vector<std::vector<uint64_t>>& mat2);
};

}  // namespace PASTA_4
