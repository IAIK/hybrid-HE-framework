#include "kreyvium_12_plain.h"

#include <math.h>

namespace KREYVIUM_12 {

static keyblock convert_key(const std::vector<uint8_t>& key) {
  keyblock k;
  for (size_t i = 0; i < k.size(); i++) {
    k[i] = (key[i / 8] >> (7 - i % 8)) & 1;
  }
  return k;
}

static std::vector<keystreamblock> convert_in(const std::vector<uint8_t>& plain,
                                              size_t num_block) {
  std::vector<keystreamblock> out;
  out.reserve(num_block);

  for (size_t i = 0; i < num_block; i++) {
    keystreamblock p;
    for (size_t k = 0; k < p.size(); k++) {
      size_t ind = (i * blocksize + k);
      p[k] = (plain[ind / 8] >> (7 - ind % 8)) & 1;
    }
    out.push_back(std::move(p));
  }
  return out;
}

static ivblock convert_iv(const std::vector<uint8_t>& iv) {
  ivblock iv_out;
  for (size_t i = 0; i < iv_out.size(); i++) {
    iv_out[i] = (iv[i / 8] >> (7 - i % 8)) & 1;
  }
  return iv_out;
}

static std::vector<uint8_t> convert_out(
    const std::vector<keystreamblock>& cipher, size_t bytes) {
  std::vector<uint8_t> result(bytes, 0);

  for (size_t i = 0; i < cipher.size(); i++) {
    for (size_t k = 0; k < blocksize; k++) {
      size_t ind = (i * blocksize + k);
      if (ind / 8 >= result.size()) return result;
      result[ind / 8] |= (cipher[i][k] << (7 - ind % 8));
    }
  }
  return result;
}

ivblock ctr(const ivblock& iv, uint64_t ctr) {
  ivblock out = iv;
  for (size_t i = IV_SIZE - 64; i < IV_SIZE; i++) {
    out[i] = iv[i] ^ ((ctr >> (IV_SIZE - i - 1)) & 1);
  }
  return out;
}

std::vector<uint8_t> Kreyvium12::encrypt(std::vector<uint8_t> plaintext,
                                         size_t bits) const {
  keyblock key = convert_key(secret_key);

  size_t num_block = ceil((double)bits / params.plain_size_bits);

  std::vector<uint8_t> iv = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x10};

  ivblock iv_ = convert_iv(iv);
  std::vector<keystreamblock> plain = convert_in(plaintext, num_block);
  std::vector<keystreamblock> result;
  result.reserve(plain.size());

  for (size_t i = 0; i < num_block; i++)
    result.push_back(plain[i] ^ keystream(key, ctr(iv_, i + 1)));

  return convert_out(result, plaintext.size());
}

std::vector<uint8_t> Kreyvium12::decrypt(std::vector<uint8_t> ciphertext,
                                         size_t bits) const {
  keyblock key = convert_key(secret_key);

  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  std::vector<uint8_t> iv = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x10};

  ivblock iv_ = convert_iv(iv);
  std::vector<keystreamblock> ciph = convert_in(ciphertext, num_block);
  std::vector<keystreamblock> result;
  result.reserve(ciph.size());

  for (size_t i = 0; i < num_block; i++)
    result.push_back(ciph[i] ^ keystream(key, ctr(iv_, i + 1)));

  return convert_out(result, ciphertext.size());
}

void Kreyvium12::prep_one_block() const {}

keystreamblock Kreyvium12::keystream(const keyblock& key,
                                     const ivblock& iv) const {
  keystreamblock out;
  stateblock state;
  ivblock inner_iv;
  keyblock inner_key;
  init(key, iv, state, inner_iv, inner_key);

  size_t warmup = 4 * STATE_SIZE;

  for (size_t i = 0; i < warmup + KREYVIUM12_PARAMS.plain_size_bits; i++) {
    bool t4 = inner_key[KREYVIUM12_PARAMS.key_size_bits - 1];
    bool t5 = inner_iv[IV_SIZE - 1];
    bool t1 = state[65] ^ state[92];
    bool t2 = state[161] ^ state[176];
    bool t3 = state[242] ^ state[287] ^ t4;
    if (i >= warmup) out[i - warmup] = t1 ^ t2 ^ t3;
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

void Kreyvium12::init(const keyblock& key, const ivblock& iv, stateblock& state,
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
  for (size_t i = 0; i < KREYVIUM12_PARAMS.key_size_bits; i++) {
    inner_key[i] = key[KREYVIUM12_PARAMS.key_size_bits - 1 - i];
  }
}

}  // namespace KREYVIUM_12
