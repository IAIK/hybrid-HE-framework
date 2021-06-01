#pragma once

#include "../plain/dasta_6_plain.h"  // for DASTA_128_params
#include "../../common/HElib_Cipher.h"

namespace DASTA_6 {

constexpr bool use_m4ri = true;

class DASTA_128_HElib : public HElibCipher {
 public:
  typedef DASTA_128 Plain;
  DASTA_128_HElib(std::vector<uint8_t> secret_key,
                  std::shared_ptr<helib::Context> con, long L, long c)
      : HElibCipher(DASTA_128_PARAMS, secret_key, con, L, c) {}

  virtual ~DASTA_128_HElib() = default;

  virtual std::string get_cipher_name() const {
    return "DASTA-HElib (n=351,r=6)";
  }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(std::vector<uint8_t>& ciphertext,
                                              size_t bits);
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertexts);

 private:
  void MultiplyWithGF2Matrix(const mzd_t* matrix,
                             std::vector<helib::Ctxt>& state);
  void MultiplyPermutedWithGF2Matrix(
      const std::array<block, blocksize>& matrix,
      const std::array<uint16_t, blocksize>& perm,
      std::vector<helib::Ctxt>& state);
  void add(std::vector<helib::Ctxt>& state,
           const std::vector<helib::Ctxt>& key);

  void sboxlayer(std::vector<helib::Ctxt>& state);
};

}  // namespace DASTA_6
