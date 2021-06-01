#include "kreyvium_12_helib.h"

using namespace helib;

namespace KREYVIUM_12 {

E_BIT& E_BIT::operator=(const E_BIT& o) noexcept {
  this->ct = o.ct;
  this->pt = o.pt;
  this->is_encrypted = o.is_encrypted;
  return *this;
}

E_BIT& E_BIT::operator=(const Ctxt& o) noexcept {
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

void E_BIT::XOR(const E_BIT& b1, const E_BIT& b2, E_BIT& r,
                const EncryptedArray& ea) {
  if (b1.is_encrypted && b2.is_encrypted) {
    r.is_encrypted = true;
    r.ct = b1.ct;
    r.ct += b2.ct;
    return;
  }

  if (b1.is_encrypted) {
    r.is_encrypted = true;
    r.ct = b1.ct;
    if (!b2.pt) {
      return;
    }
    NTL::ZZX p;
    std::vector<long> tmp(ea.size(), 0);
    tmp[0] = b2.pt;
    ea.encode(p, tmp);
    r.ct.addConstant(p);
    return;
  }

  if (b2.is_encrypted) {
    r.is_encrypted = true;
    r.ct = b2.ct;
    if (!b1.pt) {
      return;
    }
    NTL::ZZX p;
    std::vector<long> tmp(ea.size(), 0);
    tmp[0] = b1.pt;
    ea.encode(p, tmp);
    r.ct.addConstant(p);
    return;
  }

  r.is_encrypted = false;
  r.pt = b1.pt ^ b2.pt;
}

void E_BIT::XOR_inplace(E_BIT& r, const E_BIT& b, const EncryptedArray& ea) {
  if (r.is_encrypted && b.is_encrypted) {
    r.ct += b.ct;
    return;
  }

  if (r.is_encrypted) {
    if (!b.pt) return;
    NTL::ZZX p;
    std::vector<long> tmp(ea.size(), 0);
    tmp[0] = b.pt;
    ea.encode(p, tmp);
    r.ct.addConstant(p);
    return;
  }

  if (b.is_encrypted) {
    r.is_encrypted = true;
    if (!r.pt) {
      r.ct = b.ct;
      return;
    }
    NTL::ZZX p;
    std::vector<long> tmp(ea.size(), 0);
    tmp[0] = r.pt;
    ea.encode(p, tmp);
    r.ct = b.ct;
    r.ct.addConstant(p);
    return;
  }

  r.pt = r.pt ^ b.pt;
}

void E_BIT::XOR_inplace(E_BIT& r, const Ctxt& c, const EncryptedArray& ea) {
  if (r.is_encrypted) {
    r.ct += c;
    return;
  }

  r.is_encrypted = true;
  r.ct = c;
  if (!r.pt) {
    return;
  }
  NTL::ZZX p;
  std::vector<long> tmp(ea.size(), 0);
  tmp[0] = r.pt;
  ea.encode(p, tmp);
  r.ct.addConstant(p);
}

void E_BIT::XOR_plain_inplace(E_BIT& r, const bool& b,
                              const EncryptedArray& ea) {
  if (r.is_encrypted) {
    if (!b) {
      return;
    }
    NTL::ZZX p;
    std::vector<long> tmp(ea.size(), 0);
    tmp[0] = b;
    ea.encode(p, tmp);
    r.ct.addConstant(p);
    return;
  }

  r.pt ^= b;
}

void E_BIT::AND(const E_BIT& b1, const E_BIT& b2, E_BIT& r) {
  if (b1.is_encrypted && b2.is_encrypted) {
    r.is_encrypted = true;
    r.ct = b1.ct;
    r.ct.multiplyBy(b2.ct);
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

void E_BIT::AND_inplace(E_BIT& r, const E_BIT& b) {
  if (r.is_encrypted && b.is_encrypted) {
    r.ct.multiplyBy(b.ct);
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

void KREYVIUM12_HElib::encrypt_key() {
  secret_key_encrypted.clear();
  secret_key_encrypted.reserve(params.key_size_bits);
  std::vector<long> p(nslots, 0);
  for (size_t i = 0; i < params.key_size_bits; i++) {
    uint8_t bit = (secret_key[i / 8] >> (7 - i % 8)) & 1;
    Ctxt c(*he_pk);
    p[0] = bit;
    ea.encrypt(c, *he_pk, p);
    secret_key_encrypted.push_back(std::move(c));
  }
}

std::vector<Ctxt> KREYVIUM12_HElib::HE_decrypt(
    std::vector<uint8_t>& ciphertexts, size_t bits) {
  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  std::vector<uint8_t> iv_plain = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                   0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                   0x11, 0x11, 0x11, 0x10};
  ivblock iv_block = convert_iv(iv_plain);

  std::vector<E_BIT> state(STATE_SIZE, *he_pk);
  ivblock inner_iv;
  std::vector<Ctxt> inner_key(secret_key_encrypted.size(),
                              {ZeroCtxtLike, secret_key_encrypted[0]});

  std::vector<Ctxt> out(bits, {ZeroCtxtLike, secret_key_encrypted[0]});

  NTL::ZZX p;
  std::vector<long> tmp(nslots, 0);

  for (size_t b = 0; b < num_block; b++) {
    ivblock iv = ctr(iv_block, b + 1);
    // init
    for (int i = 0; i < 93; i++) {
      state[i] = secret_key_encrypted[i];
    }
    for (size_t i = 93; i < 93 + IV_SIZE; i++) {
      bool temp = iv[i - 93];
      state[i] = temp;
      inner_iv[i - 93] = iv[IV_SIZE + 92 - i];
    }
    for (size_t i = 93 + IV_SIZE; i < STATE_SIZE - 1; i++) {
      state[i] = 1;
    }
    state[STATE_SIZE - 1] = 0;
    for (size_t i = 0; i < KREYVIUM12_PARAMS.key_size_bits; i++) {
      inner_key[i] =
          secret_key_encrypted[KREYVIUM12_PARAMS.key_size_bits - 1 - i];
    }

    std::cout << "initialized..." << std::endl;

    // stream cipher
    size_t warmup = 4 * STATE_SIZE;

    for (size_t i = 0; i < warmup + KREYVIUM12_PARAMS.plain_size_bits; i++) {
      Ctxt t4 = inner_key[KREYVIUM12_PARAMS.key_size_bits - 1];
      bool t5 = inner_iv[IV_SIZE - 1];
      E_BIT t1(*he_pk);
      E_BIT::XOR(state[65], state[92], t1, ea);
      E_BIT t2(*he_pk);
      E_BIT::XOR(state[161], state[176], t2, ea);
      E_BIT t3(*he_pk);
      E_BIT::XOR(state[242], state[287], t3, ea);
      E_BIT::XOR_inplace(t3, t4, ea);
      if (i >= warmup) {
        size_t ind = b * blocksize + i - warmup;
        if (ind >= bits) break;
        // All ciphers at this point
        out[ind] = t1.cipher();
        out[ind] += t2.cipher();
        out[ind] += t3.cipher();
        int32_t bit = (ciphertexts[ind / 8] >> (7 - ind % 8)) & 1;
        if (bit) {
          tmp[0] = bit;
          ea.encode(p, tmp);
          out[ind].addConstant(p);
        }
      }
      E_BIT temp(*he_pk);
      E_BIT::XOR_inplace(t1, state[170], ea);
      E_BIT::XOR_plain_inplace(t1, t5, ea);
      E_BIT::AND(state[90], state[91], temp);
      E_BIT::XOR_inplace(t1, temp, ea);

      E_BIT::XOR_inplace(t2, state[263], ea);
      E_BIT::AND(state[174], state[175], temp);
      E_BIT::XOR_inplace(t2, temp, ea);

      E_BIT::XOR_inplace(t3, state[68], ea);
      E_BIT::AND(state[285], state[286], temp);
      E_BIT::XOR_inplace(t3, temp, ea);
      inner_key.pop_back();
      state.pop_back();
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

std::vector<uint8_t> KREYVIUM12_HElib::decrypt_result(
    std::vector<Ctxt>& ciphertexts) {
  std::vector<uint8_t> res(params.cipher_size_bytes, 0);
  std::vector<long> p;
  for (size_t i = 0; i < ciphertexts.size(); i++) {
    ea.decrypt(ciphertexts[i], he_sk, p);
    uint8_t bit = p[0] & 0x1;
    res[i / 8] |= (bit << (7 - i % 8));
  }
  return res;
}

}  // namespace KREYVIUM_12
