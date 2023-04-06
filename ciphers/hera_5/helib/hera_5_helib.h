#pragma once

#include "../../common_Zp/HElib_Cipher.h"
#include "../plain/hera_5_plain.h"  // for HERA_PARAMS

namespace HERA_5 {

class HERA_HElib : public HElibZpCipher {
 public:
  typedef HERA Plain;
  HERA_HElib(std::vector<uint64_t> secret_key,
             std::shared_ptr<helib::Context> con, long L, long c)
      : HElibZpCipher(HERA_PARAMS, secret_key, con, L, c) {}

  virtual ~HERA_HElib() = default;

  virtual std::string get_cipher_name() const {
    return "HERA-HElib (n=16,r=5)";
  }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(
      std::vector<uint64_t>& ciphertext);
  virtual std::vector<uint64_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertext);
  virtual void add_gk_indices();

 private:
  static constexpr uint64_t BSGS_N1 = 4;
  static constexpr uint64_t BSGS_N2 = 4;
  helib::Ctxt first_ark(std::vector<uint64_t>& rc);
  void ark(helib::Ctxt& state, std::vector<uint64_t>& rc);
  void sbox_cube(helib::Ctxt& state);
  void matmul(helib::Ctxt& state, std::vector<std::vector<uint64_t>>& mat);
};

}  // namespace HERA_5
