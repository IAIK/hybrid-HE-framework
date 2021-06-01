#pragma once

#include "../plain/agrasta_packed_plain.h"  // for AGRASTA_128_params
#include "../../common/HElib_Cipher.h"

namespace AGRASTA_PACKED {

class AGRASTA_128_HElib : public HElibCipher {
 public:
  typedef AGRASTA_128 Plain;
  AGRASTA_128_HElib(std::vector<uint8_t> secret_key,
                    std::shared_ptr<helib::Context> con, long L, long c)
      : HElibCipher(AGRASTA_128_PARAMS, secret_key, con, L, c, true) {}

  virtual ~AGRASTA_128_HElib() = default;

  virtual std::string get_cipher_name() const {
    return "AGRASTA-PACKED-HElib (n=129,r=4)";
  }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(std::vector<uint8_t>& ciphertext,
                                              size_t bits);
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertexts);

 private:
  static constexpr uint64_t BSGS_N1 = 43;
  static constexpr uint64_t BSGS_N2 = 3;

  void MultiplyWithGF2Matrix(const std::vector<std::vector<uint8_t>>& mat,
                             helib::Ctxt& state);
  void addConstant(helib::Ctxt& state, const std::vector<uint8_t>& constant);

  void sboxlayer(helib::Ctxt& state);
};

}  // namespace AGRASTA_PACKED
