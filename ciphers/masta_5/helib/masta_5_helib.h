#pragma once

#include "../../common_Zp/HElib_Cipher.h"
#include "../plain/masta_5_plain.h"  // for MASTA_128_PARAMS

namespace MASTA_5 {

class MASTA_128_HElib : public HElibZpCipher {
 public:
  typedef MASTA_128 Plain;
  MASTA_128_HElib(std::vector<uint64_t> secret_key,
                  std::shared_ptr<helib::Context> con, long L, long c)
      : HElibZpCipher(MASTA_128_PARAMS, secret_key, con, L, c, true) {}

  virtual ~MASTA_128_HElib() = default;

  virtual std::string get_cipher_name() const {
    return "MASTA-HElib (n=64,r=5)";
  }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(
      std::vector<uint64_t>& ciphertext);
  virtual std::vector<uint64_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertext);
  virtual void add_gk_indices();

 private:
  static constexpr uint64_t BSGS_N1 = 8;
  static constexpr uint64_t BSGS_N2 = 8;

  void add_rc(helib::Ctxt& state, std::vector<uint64_t>& rc);
  void sbox(helib::Ctxt& state);
  void matmul(helib::Ctxt& state, std::vector<std::vector<uint64_t>>& mat);
};

}  // namespace MASTA_5
