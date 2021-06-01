#pragma once

#include "../plain/rasta_6_plain.h"  // for RASTA_128_params
#include "../../common/HElib_Cipher.h"

namespace RASTA_6 {

constexpr bool use_m4ri = true;

class RASTA_128_HElib : public HElibCipher {
 public:
  typedef RASTA_128 Plain;
  RASTA_128_HElib(std::vector<uint8_t> secret_key,
                  std::shared_ptr<helib::Context> con, long L, long c)
      : HElibCipher(RASTA_128_PARAMS, secret_key, con, L, c) {}

  virtual ~RASTA_128_HElib() = default;

  virtual std::string get_cipher_name() const {
    return "RASTA-HElib (n=351,r=6)";
  }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(std::vector<uint8_t>& ciphertext,
                                              size_t bits);
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertexts);

 private:
  void MultiplyWithGF2Matrix(const mzd_t* matrix,
                             std::vector<helib::Ctxt>& state);
  void MultiplyWithGF2Matrix(const std::vector<block>& matrix,
                             std::vector<helib::Ctxt>& state);
  void addConstant(std::vector<helib::Ctxt>& state, const block& constant);
  void add(std::vector<helib::Ctxt>& state,
           const std::vector<helib::Ctxt>& key);

  void sboxlayer(std::vector<helib::Ctxt>& state);
};

}  // namespace RASTA_6
