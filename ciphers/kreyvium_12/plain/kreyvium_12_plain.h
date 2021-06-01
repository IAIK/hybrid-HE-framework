#pragma once

#include <bitset>
#include <string>
#include <vector>

#include "../../common/Cipher.h"

namespace KREYVIUM_12 {

constexpr BlockCipherParams KREYVIUM12_PARAMS = {16, 128, 6, 46, 6, 46};

constexpr unsigned blocksize =
    KREYVIUM12_PARAMS.plain_size_bits;  // Block size in bits
constexpr unsigned STATE_SIZE = 288;
constexpr unsigned IV_SIZE = KREYVIUM12_PARAMS.key_size_bits;

typedef std::bitset<STATE_SIZE> stateblock;
typedef std::bitset<IV_SIZE> ivblock;
typedef std::bitset<KREYVIUM12_PARAMS.key_size_bits> keyblock;
typedef std::bitset<blocksize> keystreamblock;

ivblock ctr(const ivblock& iv, uint64_t ctr);

class Kreyvium12 : public BlockCipher {
 public:
  Kreyvium12(std::vector<uint8_t> secret_key)
      : BlockCipher(KREYVIUM12_PARAMS, secret_key) {}

  virtual ~Kreyvium12() = default;

  virtual std::string get_cipher_name() const { return "KREYVIUM-12 (N=46)"; }
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

}  // namespace KREYVIUM_12
