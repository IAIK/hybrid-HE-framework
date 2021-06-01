#pragma once

#include "../plain/dasta_5_packed_plain.h"  // for DASTA_128_params
#include "../../common/HElib_Cipher.h"

namespace DASTA_5_PACKED {

class DASTA_128_HElib : public HElibCipher {
 public:
  typedef DASTA_128 Plain;
  DASTA_128_HElib(std::vector<uint8_t> secret_key,
                  std::shared_ptr<helib::Context> con, long L, long c)
      : HElibCipher(DASTA_128_PARAMS, secret_key, con, L, c, true) {}

  virtual ~DASTA_128_HElib() = default;

  virtual std::string get_cipher_name() const {
    return "DASTA-PACKED-HElib (n=525,r=5)";
  }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(std::vector<uint8_t>& ciphertext,
                                              size_t bits);
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertexts);

 private:
  static constexpr uint64_t BSGS_N1 = 25;
  static constexpr uint64_t BSGS_N2 = 21;

  void MultiplyWithGF2Matrix(const std::vector<std::vector<uint8_t>>& mat,
                             helib::Ctxt& state);

  void sboxlayer(helib::Ctxt& state);
};

}  // namespace DASTA_5_PACKED
