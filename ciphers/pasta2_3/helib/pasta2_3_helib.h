#pragma once

#include "../../common_Zp/HElib_Cipher.h"
#include "../plain/pasta2_3_plain.h"  // for PASTA_params

namespace PASTA2_3 {

class PASTA2_HElib : public HElibZpCipher {
 public:
  typedef PASTA2 Plain;
  PASTA2_HElib(std::vector<uint64_t> secret_key,
               std::shared_ptr<helib::Context> con, long L, long c)
      : HElibZpCipher(PASTA2_PARAMS, secret_key, con, L, c, true),
        instance(plain_mod),
        halfslots(nslots >> 1) {}

  virtual ~PASTA2_HElib() = default;

  virtual std::string get_cipher_name() const {
    return "PASTA2-HElib (n=128,r=3)";
  }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(
      std::vector<uint64_t>& ciphertext);
  virtual std::vector<uint64_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertext);
  virtual void add_gk_indices();

 private:
  static constexpr bool REMOVE_SECOND_VEC = false;
  static constexpr uint64_t BSGS_N1 = 16;
  static constexpr uint64_t BSGS_N2 = 8;

  Pasta2Instance instance;
  size_t halfslots;

  void sbox_feistel(helib::Ctxt& state);
  void sbox_cube(helib::Ctxt& state);
  void matmul(helib::Ctxt& state, std::vector<NTL::ZZX>& mat);
  void add_rc(helib::Ctxt& state, size_t r);
  void add_rc(helib::Ctxt& state, std::vector<uint64_t>& rc);
  void mix(helib::Ctxt& state);

  void diagonal(helib::Ctxt& state, std::vector<NTL::ZZX>& mat);
  void babystep_giantstep(helib::Ctxt& state, std::vector<NTL::ZZX>& mat);

  std::vector<NTL::ZZX> encode_mat(
      const std::vector<std::vector<uint64_t>>& mat1,
      const std::vector<std::vector<uint64_t>>& mat2);
  std::vector<NTL::ZZX> encode_babystep_giantstep(
      const std::vector<std::vector<uint64_t>>& mat1,
      const std::vector<std::vector<uint64_t>>& mat2);
  std::vector<NTL::ZZX> encode_diagonal(
      const std::vector<std::vector<uint64_t>>& mat1,
      const std::vector<std::vector<uint64_t>>& mat2);
};

}  // namespace PASTA2_3
