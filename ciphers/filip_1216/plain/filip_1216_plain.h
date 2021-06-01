#pragma once

#include <array>
#include <bitset>
#include <string>
#include <vector>

#include "aes.h"
#include "../../common/Cipher.h"

namespace FILIP_1216 {

// Blockcipher just for testing a plaintext/ciphertext with specific size
constexpr BlockCipherParams FILIP_1216_PARAMS = {2048, 16384, 8, 64, 8, 64};

class FiLIP_1216 : public BlockCipher {
 public:
  FiLIP_1216(std::vector<uint8_t> secret_key)
      : BlockCipher(FILIP_1216_PARAMS, secret_key) {}

  virtual ~FiLIP_1216() = default;

  virtual std::string get_cipher_name() const { return "FiLIP_1216"; }
  virtual std::vector<uint8_t> encrypt(std::vector<uint8_t> plaintext,
                                       size_t bits) const;
  virtual std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext,
                                       size_t bits) const;

  virtual void prep_one_block() const;
};

constexpr size_t SIZE = 8;
constexpr size_t MF[SIZE] = {128, 64, 0, 80, 0, 0, 0, 80};
constexpr size_t NB_VAR = 1216;
typedef std::bitset<FILIP_1216_PARAMS.key_size_bits>
    state;  // Store messages and states
typedef std::bitset<NB_VAR> state_whitened;

//------------------------------------------------------------------------
//------------------------------------------------------------------------
// FiLIP CORE
//------------------------------------------------------------------------
//------------------------------------------------------------------------

class FiLIP {
 private:
  BlockCipherParams params;
  uint8_t flag;
  osuCrypto::AES aes;
  osuCrypto::block aes_random;
  osuCrypto::block aes_ctxt;

  uint32_t aes_forward_secure();

  void ctr(std::array<uint8_t, 16>& iv, uint64_t counter);

 public:
  FiLIP(BlockCipherParams param, state k = 0);

  void set_iv(std::array<uint8_t, 16>& iv);
  state key = 0;

  void set_whitening(state_whitened& whitening);
  void shuffle(std::vector<size_t>& ind);
  uint8_t FLIP(state_whitened& state);
  std::vector<uint8_t> keystream(std::array<uint8_t, 16>& iv, size_t bits);
};

}  // namespace FILIP_1216
