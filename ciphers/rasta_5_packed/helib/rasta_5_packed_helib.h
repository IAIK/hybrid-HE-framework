#pragma once

#include "../plain/rasta_5_packed_plain.h"  // for RASTA_128_params
#include "../../common/HElib_Cipher.h"

namespace RASTA_5_PACKED {

class RASTA_128_HElib : public HElibCipher {
 public:
  typedef RASTA_128 Plain;
  RASTA_128_HElib(std::vector<uint8_t> secret_key,
                  std::shared_ptr<helib::Context> con, long L, long c)
      : HElibCipher(RASTA_128_PARAMS, secret_key, con, L, c, true) {}

  virtual ~RASTA_128_HElib() = default;

  virtual std::string get_cipher_name() const {
    return "RASTA-PACKED-HElib (n=525,r=5)";
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
  void addConstant(helib::Ctxt& state, const std::vector<uint8_t>& constant);

  void sboxlayer(helib::Ctxt& state);
};

}  // namespace RASTA_5_PACKED
