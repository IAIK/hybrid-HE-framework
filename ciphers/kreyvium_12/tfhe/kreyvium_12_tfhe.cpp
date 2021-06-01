#include "kreyvium_12_tfhe.h"

#include <iostream>

namespace KREYVIUM_12 {

E_BIT& E_BIT::operator=(const E_BIT& o) noexcept {
  this->ct = o.ct;
  this->pt = o.pt;
  this->is_encrypted = o.is_encrypted;
  return *this;
}

E_BIT& E_BIT::operator=(const TFHECiphertext& o) noexcept {
  this->ct = o;
  this->pt = false;
  this->is_encrypted = true;
  return *this;
}

E_BIT& E_BIT::operator=(const bool o) noexcept {
  this->pt = o;
  this->is_encrypted = false;
  return *this;
}

E_BIT& E_BIT::operator=(LweSample& o) noexcept {
  this->ct = o;
  this->pt = false;
  this->is_encrypted = true;
  return *this;
}

void E_BIT::XOR(const E_BIT& b1, const E_BIT& b2, E_BIT& r,
                const TFheGateBootstrappingCloudKeySet* pk) {
  if (b1.is_encrypted && b2.is_encrypted) {
    r.is_encrypted = true;
    bootsXOR(r.ct, b1.ct, b2.ct, pk);
    return;
  }

  if (b1.is_encrypted) {
    r.is_encrypted = true;
    if (!b2.pt) {
      r.ct = b1.ct;
      return;
    }
    bootsNOT(r.ct, b1.ct, pk);

    return;
  }

  if (b2.is_encrypted) {
    r.is_encrypted = true;
    if (!b1.pt) {
      r.ct = b2.ct;
      return;
    }
    bootsNOT(r.ct, b2.ct, pk);
    return;
  }

  r.is_encrypted = false;
  r.pt = b1.pt ^ b2.pt;
}

void E_BIT::XOR_inplace(E_BIT& r, const E_BIT& b,
                        const TFheGateBootstrappingCloudKeySet* pk) {
  if (r.is_encrypted && b.is_encrypted) {
    bootsXOR(r.ct, r.ct, b.ct, pk);
    return;
  }

  if (r.is_encrypted) {
    if (!b.pt) return;
    bootsNOT(r.ct, r.ct, pk);
    return;
  }

  if (b.is_encrypted) {
    r.is_encrypted = true;
    if (!r.pt) {
      r.ct = b.ct;
      return;
    }
    bootsNOT(r.ct, b.ct, pk);
    return;
  }

  r.pt = r.pt ^ b.pt;
}

void E_BIT::XOR_inplace(E_BIT& r, const TFHECiphertext& c,
                        const TFheGateBootstrappingCloudKeySet* pk) {
  if (r.is_encrypted) {
    bootsXOR(r.ct, r.ct, c, pk);
    return;
  }

  r.is_encrypted = true;
  if (!r.pt) {
    r.ct = c;
    return;
  }
  bootsNOT(r.ct, c, pk);
}

void E_BIT::XOR_plain_inplace(E_BIT& r, const bool& b,
                              const TFheGateBootstrappingCloudKeySet* pk) {
  if (r.is_encrypted) {
    if (!b) {
      return;
    }
    bootsNOT(r.ct, r.ct, pk);
  }

  r.pt ^= b;
}

void E_BIT::AND(const E_BIT& b1, const E_BIT& b2, E_BIT& r,
                const TFheGateBootstrappingCloudKeySet* pk) {
  if (b1.is_encrypted && b2.is_encrypted) {
    r.is_encrypted = true;
    bootsAND(r.ct, b1.ct, b2.ct, pk);
    return;
  }

  if (b1.is_encrypted) {
    if (b2.pt) {
      r.is_encrypted = true;
      r.ct = b1.ct;
      return;
    }
    r.is_encrypted = false;
    r.pt = 0;
    return;
  }

  if (b2.is_encrypted) {
    if (b1.pt) {
      r.is_encrypted = true;
      r.ct = b2.ct;
      return;
    }
    r.is_encrypted = false;
    r.pt = 0;
    return;
  }

  r.is_encrypted = false;
  r.pt = b1.pt & b2.pt;
}

void E_BIT::AND_inplace(E_BIT& r, const E_BIT& b,
                        const TFheGateBootstrappingCloudKeySet* pk) {
  if (r.is_encrypted && b.is_encrypted) {
    bootsAND(r.ct, r.ct, b.ct, pk);
    return;
  }

  if (r.is_encrypted) {
    if (b.pt) return;
    r.is_encrypted = false;
    r.pt = 0;
    return;
  }

  if (b.is_encrypted) {
    if (r.pt) {
      r.is_encrypted = true;
      r.ct = b.ct;
      return;
    }
    r.is_encrypted = false;
    r.pt = false;
    return;
  }

  r.pt = r.pt & b.pt;
}

static ivblock convert_iv(const std::vector<uint8_t>& iv) {
  ivblock iv_out;
  for (size_t i = 0; i < iv_out.size(); i++) {
    iv_out[i] = (iv[i / 8] >> (7 - i % 8)) & 1;
  }
  return iv_out;
}

void KREYVIUM12_TFHE::encrypt_key() {
  secret_key_encrypted.init(params.key_size_bits, context);
  for (size_t i = 0; i < params.key_size_bits; i++) {
    uint8_t bit = (secret_key[i / 8] >> (7 - i % 8)) & 1;
    bootsSymEncrypt(&secret_key_encrypted[i], bit, he_sk);
  }
}

TFHECiphertextVec KREYVIUM12_TFHE::HE_decrypt(std::vector<uint8_t>& ciphertexts,
                                              size_t bits) {
  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  std::vector<uint8_t> iv_plain = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                   0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                   0x11, 0x11, 0x11, 0x10};
  ivblock iv_block = convert_iv(iv_plain);

  std::vector<E_BIT> state(STATE_SIZE, context);

  ivblock inner_iv;
  std::vector<TFHECiphertext> inner_key(secret_key_encrypted.size(), context);

  TFHECiphertextVec out(bits, context);

  for (size_t b = 0; b < num_block; b++) {
    ivblock iv = ctr(iv_block, b + 1);
    // init
    for (int i = 0; i < 93; i++) {
      state[i] = secret_key_encrypted[i];
    }
    for (size_t i = 93; i < 93 + IV_SIZE; i++) {
      bool tmp = iv[i - 93];
      state[i] = tmp;
      inner_iv[i - 93] = iv[IV_SIZE + 92 - i];
    }
    for (size_t i = 93 + IV_SIZE; i < STATE_SIZE - 1; i++) {
      state[i] = 1;
    }
    state[STATE_SIZE - 1] = 0;
    for (size_t i = 0; i < KREYVIUM12_PARAMS.key_size_bits; i++) {
      lweCopy(inner_key[i],
              &secret_key_encrypted[KREYVIUM12_PARAMS.key_size_bits - 1 - i],
              he_pk->params->in_out_params);
    }

    std::cout << "initialized..." << std::endl;

    // stream cipher
    size_t warmup = 4 * STATE_SIZE;

    for (size_t i = 0; i < warmup + KREYVIUM12_PARAMS.plain_size_bits; i++) {
      TFHECiphertext t4 = inner_key[KREYVIUM12_PARAMS.key_size_bits - 1];
      bool t5 = inner_iv[IV_SIZE - 1];
      E_BIT t1(context);
      E_BIT::XOR(state[65], state[92], t1, he_pk);
      E_BIT t2(context);
      E_BIT::XOR(state[161], state[176], t2, he_pk);
      E_BIT t3(context);
      E_BIT::XOR(state[242], state[287], t3, he_pk);
      E_BIT::XOR_inplace(t3, t4, he_pk);
      if (i >= warmup) {
        size_t ind = b * blocksize + i - warmup;
        if (ind >= bits) break;
        // All ciphers at this point
        bootsXOR(&out[ind], t1.cipher(), t2.cipher(), he_pk);
        bootsXOR(&out[ind], &out[ind], t3.cipher(), he_pk);

        // add ciphertext
        int32_t bit = (ciphertexts[ind / 8] >> (7 - ind % 8)) & 1;
        if (bit) {
          bootsNOT(&out[ind], &out[ind], he_pk);
        }
      }
      E_BIT tmp(context);
      E_BIT::XOR_inplace(t1, state[170], he_pk);
      E_BIT::XOR_plain_inplace(t1, t5, he_pk);
      E_BIT::AND(state[90], state[91], tmp, he_pk);
      E_BIT::XOR_inplace(t1, tmp, he_pk);

      E_BIT::XOR_inplace(t2, state[263], he_pk);
      E_BIT::AND(state[174], state[175], tmp, he_pk);
      E_BIT::XOR_inplace(t2, tmp, he_pk);

      E_BIT::XOR_inplace(t3, state[68], he_pk);
      E_BIT::AND(state[285], state[286], tmp, he_pk);
      E_BIT::XOR_inplace(t3, tmp, he_pk);
      state.pop_back();
      inner_key.pop_back();
      inner_iv <<= 1;
      state.emplace(state.begin(), std::move(t3));
      state[93] = t1;
      state[177] = t2;
      inner_key.emplace(inner_key.begin(), std::move(t4));
      inner_iv[0] = t5;
    }
  }
  return out;
}

std::vector<uint8_t> KREYVIUM12_TFHE::decrypt_result(
    TFHECiphertextVec& ciphertexts) {
  std::vector<uint8_t> res(params.cipher_size_bytes, 0);
  for (size_t i = 0; i < ciphertexts.size(); i++) {
    uint8_t bit = bootsSymDecrypt(&ciphertexts[i], he_sk) & 0x1;
    res[i / 8] |= (bit << (7 - i % 8));
  }
  return res;
}

}  // namespace KREYVIUM_12
