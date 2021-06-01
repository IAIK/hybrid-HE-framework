#pragma once

#include "../plain/kreyvium_13_plain.h"  // for KREYVIUM13_PARAMS
#include "../../common/HElib_Cipher.h"

namespace KREYVIUM_13 {

class E_BIT {
 private:
  helib::Ctxt ct;
  bool pt;
  bool is_encrypted;

 public:
  E_BIT(helib::PubKey& pk) : ct(pk), pt(false), is_encrypted(false){};
  E_BIT(const bool p, helib::PubKey& pk) : ct(pk), pt(p), is_encrypted(false){};
  E_BIT(const helib::Ctxt& c) : ct(c), is_encrypted(true){};
  E_BIT(E_BIT&& o)
  noexcept
      : ct(std::move(o.ct)),
        pt(std::exchange(o.pt, false)),
        is_encrypted(std::exchange(o.is_encrypted, false)){};
  E_BIT(const E_BIT& o) : ct(o.ct), pt(o.pt), is_encrypted(o.is_encrypted){};
  E_BIT& operator=(const E_BIT& o) noexcept;
  E_BIT& operator=(const helib::Ctxt& o) noexcept;
  E_BIT& operator=(const bool o) noexcept;

  const helib::Ctxt& cipher() const { return ct; };
  const bool& plain() const { return pt; };

  static void XOR(const E_BIT& b1, const E_BIT& b2, E_BIT& r,
                  const helib::EncryptedArray& ea);
  static void XOR_inplace(E_BIT& r, const E_BIT& b,
                          const helib::EncryptedArray& ea);
  static void XOR_inplace(E_BIT& r, const helib::Ctxt& c,
                          const helib::EncryptedArray& ea);
  static void XOR_plain_inplace(E_BIT& r, const bool& b,
                                const helib::EncryptedArray& ea);
  static void AND(const E_BIT& b1, const E_BIT& b2, E_BIT& r);
  static void AND_inplace(E_BIT& r, const E_BIT& b);
};

class KREYVIUM13_HElib : public HElibCipher {
 public:
  typedef Kreyvium13 Plain;
  KREYVIUM13_HElib(std::vector<uint8_t> secret_key,
                   std::shared_ptr<helib::Context> con, long L, long c)
      : HElibCipher(KREYVIUM13_PARAMS, secret_key, con, L, c) {}

  virtual ~KREYVIUM13_HElib() = default;

  virtual std::string get_cipher_name() const {
    return "KREYVIUM-13-HElib (N=125)";
  }
  virtual void encrypt_key();
  virtual std::vector<helib::Ctxt> HE_decrypt(std::vector<uint8_t>& ciphertext,
                                              size_t bits);
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertexts);
};

}  // namespace KREYVIUM_13
