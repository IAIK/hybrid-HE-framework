#include "filip_1216_helib.h"

using namespace helib;

namespace FILIP_1216 {

void FiLIP_1216_HElib::encrypt_key() {
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

std::vector<Ctxt> FiLIP_1216_HElib::HE_decrypt(
    std::vector<uint8_t>& ciphertexts, size_t bits) {
  std::array<uint8_t, 16> iv = {0xab, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  FiLIP filip(params);

  std::vector<Ctxt> out(bits, {ZeroCtxtLike, secret_key_encrypted[0]});
  std::vector<Ctxt> whitened(NB_VAR, {ZeroCtxtLike, secret_key_encrypted[0]});
  std::vector<size_t> ind;
  ind.reserve(params.key_size_bits);
  for (size_t i = 0; i < params.key_size_bits; i++) ind.push_back(i);

  state_whitened whitening;

  NTL::ZZX p;
  std::vector<long> tmp(nslots, 0);

  filip.set_iv(iv);

  for (size_t i = 0; i < bits; i++) {
    filip.shuffle(ind);
    filip.set_whitening(whitening);
    for (size_t j = 0; j < NB_VAR; j++) {
      whitened[j] = secret_key_encrypted[ind[j]];
      if (!whitening[j]) continue;
      tmp[0] = whitening[j];
      ea.encode(p, tmp);
      whitened[j].addConstant(p);
    }
    FLIP(whitened, out[i]);
    int32_t bit = (ciphertexts[i / 8] >> (7 - i % 8)) & 1;
    if (!bit) continue;
    tmp[0] = bit;
    ea.encode(p, tmp);
    out[i].addConstant(p);
  }

  return out;
}

std::vector<uint8_t> FiLIP_1216_HElib::decrypt_result(
    std::vector<Ctxt>& ciphertexts) {
  size_t size = ceil((double)ciphertexts.size() / 8);
  std::vector<uint8_t> res(size, 0);
  std::vector<long> p;
  for (size_t i = 0; i < ciphertexts.size(); i++) {
    ea.decrypt(ciphertexts[i], he_sk, p);
    uint8_t bit = p[0] & 0x1;
    res[i / 8] |= (bit << (7 - i % 8));
  }
  return res;
}

void FiLIP_1216_HElib::FLIP(std::vector<Ctxt>& state, Ctxt& out) {
  size_t nb = 0;

  // Computation of Linear monomials
  out = state[nb++];
  for (size_t i = 1; i < MF[0]; i++) out += state[nb++];

  // Computation of higher degree monomials
  for (size_t i = 1; i < SIZE; i++) {
    for (size_t j = 0; j < MF[i]; j++) {
      std::vector<Ctxt> tree;
      tree.reserve((i + 1));
      tree.push_back(state[nb++]);
      tree.push_back(state[nb++]);
      for (size_t k = 2; k < (i + 1); k++) tree.push_back(state[nb++]);
      treeMul(tree);
      out += tree[0];
    }
  }
}

void FiLIP_1216_HElib::treeMul(std::vector<helib::Ctxt>& tree) {
  auto len = tree.size();

  // tree mul
  while (len != 1) {
    auto new_len = len / 2;
    for (unsigned int i = 0; i < new_len; i++) {
      tree[2 * i].multiplyBy(tree[2 * i + 1]);
      tree[i] = tree[2 * i];
    }
    if (len % 2) {
      tree[new_len] = tree[len - 1];
      new_len++;
    }
    // multree.resize(new_len);
    len = new_len;
  }
}

}  // namespace FILIP_1216
