#pragma once

#include "../plain/lowmc_plain.h"  // for LOWMC_256_128_63_14_PARAMS
#include "../../common/HElib_Cipher.h"

namespace LOWMC {

constexpr bool use_m4ri = true;

class LOWMC_256_128_63_14_HElib : public HElibCipher {
 public:
  typedef LOWMC_256_128_63_14 Plain;
  LOWMC_256_128_63_14_HElib(std::vector<uint8_t> secret_key,
                            std::shared_ptr<helib::Context> con, long L, long c)
      : HElibCipher(LOWMC_256_128_63_14_PARAMS, secret_key, con, L, c) {}

  virtual ~LOWMC_256_128_63_14_HElib() = default;

  virtual std::string get_cipher_name() const {
    return "LOWMC-HElib (n=256,k=128,m=63,r=14,d=128)";
  }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(std::vector<uint8_t>& ciphertext,
                                              size_t bits);
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertexts);

 private:
  std::vector<helib::Ctxt> MultiplyWithGF2Matrix(
      const std::vector<keyblock>& matrix, const std::vector<helib::Ctxt>& k);
  void MultiplyWithGF2MatrixAndAdd(const std::vector<keyblock>& matrix,
                                   const std::vector<helib::Ctxt>& key,
                                   std::vector<helib::Ctxt>& state);
  void MultiplyWithGF2Matrix(const std::vector<block>& matrix,
                             std::vector<helib::Ctxt>& state);

  void MultiplyWithGF2MatrixAndAdd(const mzd_t* matrix,
                                   const std::vector<helib::Ctxt>& key,
                                   std::vector<helib::Ctxt>& state);
  void MultiplyWithGF2Matrix(const mzd_t* matrix,
                             std::vector<helib::Ctxt>& state);

  void addConstant(std::vector<helib::Ctxt>& state, const block& constant);

  void sboxlayer(std::vector<helib::Ctxt>& state);
  void Sbox(helib::Ctxt& a, helib::Ctxt& b, helib::Ctxt& c);
  void invSbox(helib::Ctxt& a, helib::Ctxt& b, helib::Ctxt& c);
};

}  // namespace LOWMC
