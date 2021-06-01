#include "kreyvium_plain.h"

#include <math.h>

namespace KREYVIUM {

static keyblock convert_key(const std::vector<uint8_t>& key) {
  keyblock k;
  for (size_t i = 0; i < k.size(); i++) {
    k[i] = (key[i / 8] >> (7 - i % 8)) & 1;
  }
  return k;
}

static ivblock convert_iv(const std::vector<uint8_t>& iv) {
  ivblock iv_out;
  for (size_t i = 0; i < iv_out.size(); i++) {
    iv_out[i] = (iv[i / 8] >> (7 - i % 8)) & 1;
  }
  return iv_out;
}

std::vector<uint8_t> Kreyvium::encrypt(std::vector<uint8_t> plaintext,
                                       size_t bits) const {
  keyblock key = convert_key(secret_key);

  std::vector<uint8_t> iv = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};

  ivblock iv_ = convert_iv(iv);
  std::vector<uint8_t> ks = keystream(key, iv_, bits);
  for (size_t i = 0; i < ks.size(); i++) ks[i] ^= plaintext[i];
  return ks;
}

std::vector<uint8_t> Kreyvium::decrypt(std::vector<uint8_t> ciphertext,
                                       size_t bits) const {
  keyblock key = convert_key(secret_key);

  std::vector<uint8_t> iv = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};

  ivblock iv_ = convert_iv(iv);
  std::vector<uint8_t> ks = keystream(key, iv_, bits);
  for (size_t i = 0; i < ks.size(); i++) ks[i] ^= ciphertext[i];
  return ks;
}

void Kreyvium::prep_one_block() const {}

std::vector<uint8_t> Kreyvium::keystream(const keyblock& key, const ivblock& iv,
                                         size_t bits) const {
  size_t bytes = ceil((double)bits / 8);
  std::vector<uint8_t> out(bytes, 0);

  stateblock state;
  ivblock inner_iv;
  keyblock inner_key;
  init(key, iv, state, inner_iv, inner_key);

  size_t warmup = 4 * STATE_SIZE;

  for (size_t i = 0; i < warmup + bits; i++) {
    bool t4 = inner_key[KREYVIUM_PARAMS.key_size_bits - 1];
    bool t5 = inner_iv[IV_SIZE - 1];
    bool t1 = state[65] ^ state[92];
    bool t2 = state[161] ^ state[176];
    bool t3 = state[242] ^ state[287] ^ t4;
    if (i >= warmup) {
      size_t ind = i - warmup;
      out[ind / 8] |= ((t1 ^ t2 ^ t3) << (7 - ind % 8));
    }
    t1 = t1 ^ (state[90] & state[91]) ^ state[170] ^ t5;
    t2 = t2 ^ (state[174] & state[175]) ^ state[263];
    t3 = t3 ^ (state[285] & state[286]) ^ state[68];
    state <<= 1;
    inner_key <<= 1;
    inner_iv <<= 1;
    state[0] = t3;
    state[93] = t1;
    state[177] = t2;
    inner_key[0] = t4;
    inner_iv[0] = t5;
  }
  return out;
}

void Kreyvium::init(const keyblock& key, const ivblock& iv, stateblock& state,
                    ivblock& inner_iv, keyblock& inner_key) const {
  for (int i = 0; i < 93; i++) {
    state[i] = key[i];
  }
  for (size_t i = 93; i < 93 + IV_SIZE; i++) {
    state[i] = iv[i - 93];
    inner_iv[i - 93] = iv[IV_SIZE + 92 - i];
  }
  for (size_t i = 93 + IV_SIZE; i < STATE_SIZE - 1; i++) {
    state[i] = 1;
  }
  state[STATE_SIZE - 1] = 0;
  for (size_t i = 0; i < KREYVIUM_PARAMS.key_size_bits; i++) {
    inner_key[i] = key[KREYVIUM_PARAMS.key_size_bits - 1 - i];
  }
}

}  // namespace KREYVIUM
