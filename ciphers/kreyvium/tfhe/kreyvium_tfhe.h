#pragma once

#include "../plain/kreyvium_plain.h"  // for KREYVIUM_PARAMS
#include "../../common/TFHE_Cipher.h"

namespace KREYVIUM {

class E_BIT {
 private:
  TFHECiphertext ct;
  bool pt;
  bool is_encrypted;

 public:
  E_BIT() : pt(false), is_encrypted(false){};
  E_BIT(const bool p) : pt(p), is_encrypted(false){};
  E_BIT(TFheGateBootstrappingParameterSet* c) : ct(c), is_encrypted(false){};
  E_BIT(const TFHECiphertext& c) : ct(c), is_encrypted(true){};
  E_BIT(const E_BIT& o) : ct(o.ct), pt(o.pt), is_encrypted(o.is_encrypted){};
  E_BIT(E_BIT&& o)
  noexcept
      : ct(std::move(o.ct)),
        pt(std::exchange(o.pt, false)),
        is_encrypted(std::exchange(o.is_encrypted, false)){};
  E_BIT& operator=(const E_BIT& o) noexcept;
  E_BIT& operator=(const TFHECiphertext& o) noexcept;
  E_BIT& operator=(LweSample& o) noexcept;
  E_BIT& operator=(const bool o) noexcept;

  const TFHECiphertext& cipher() const { return ct; };
  const bool& plain() const { return pt; };

  static void XOR(const E_BIT& b1, const E_BIT& b2, E_BIT& r,
                  const TFheGateBootstrappingCloudKeySet* pk);
  static void XOR_inplace(E_BIT& r, const E_BIT& b,
                          const TFheGateBootstrappingCloudKeySet* pk);
  static void XOR_inplace(E_BIT& r, const TFHECiphertext& c,
                          const TFheGateBootstrappingCloudKeySet* pk);
  static void XOR_plain_inplace(E_BIT& r, const bool& b,
                                const TFheGateBootstrappingCloudKeySet* pk);
  static void AND(const E_BIT& b1, const E_BIT& b2, E_BIT& r,
                  const TFheGateBootstrappingCloudKeySet* pk);
  static void AND_inplace(E_BIT& r, const E_BIT& b,
                          const TFheGateBootstrappingCloudKeySet* pk);
};

class KREYVIUM_TFHE : public TFHECipher {
 public:
  typedef Kreyvium Plain;
  KREYVIUM_TFHE(std::vector<uint8_t> secret_key, int seclevel = 128)
      : TFHECipher(KREYVIUM_PARAMS, secret_key, seclevel) {}

  virtual ~KREYVIUM_TFHE() = default;

  virtual std::string get_cipher_name() const { return "KREYVIUM-TFHE"; }
  virtual void encrypt_key();
  virtual TFHECiphertextVec HE_decrypt(std::vector<uint8_t>& ciphertext,
                                       size_t bits);
  virtual std::vector<uint8_t> decrypt_result(TFHECiphertextVec& ciphertexts);
};

}  // namespace KREYVIUM
