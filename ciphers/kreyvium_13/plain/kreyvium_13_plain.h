#pragma once

#include <bitset>
#include <string>
#include <vector>

#include "../../common/Cipher.h"

namespace KREYVIUM_13 {

constexpr BlockCipherParams KREYVIUM13_PARAMS = {16, 128, 16, 125, 16, 125};

constexpr unsigned blocksize =
    KREYVIUM13_PARAMS.plain_size_bits;  // Block size in bits
constexpr unsigned STATE_SIZE = 288;
constexpr unsigned IV_SIZE = KREYVIUM13_PARAMS.key_size_bits;

typedef std::bitset<STATE_SIZE> stateblock;
typedef std::bitset<IV_SIZE> ivblock;
typedef std::bitset<KREYVIUM13_PARAMS.key_size_bits> keyblock;
typedef std::bitset<blocksize> keystreamblock;

ivblock ctr(const ivblock& iv, uint64_t ctr);

class Kreyvium13 : public BlockCipher {
 public:
  Kreyvium13(std::vector<uint8_t> secret_key)
      : BlockCipher(KREYVIUM13_PARAMS, secret_key) {}

  virtual ~Kreyvium13() = default;

  virtual std::string get_cipher_name() const { return "KREYVIUM-13 (N=125)"; }
  virtual std::vector<uint8_t> encrypt(std::vector<uint8_t> plaintext,
                                       size_t bits) const;
  virtual std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext,
                                       size_t bits) const;

  virtual void prep_one_block() const;

 private:
  keystreamblock keystream(const keyblock& key, const ivblock& iv) const;
  void init(const keyblock& key, const ivblock& iv, stateblock& state,
            ivblock& inner_iv, keyblock& inner_key) const;
};

}  // namespace KREYVIUM_13
