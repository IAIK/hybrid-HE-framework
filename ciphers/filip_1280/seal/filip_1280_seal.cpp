#include "filip_1280_seal.h"

using namespace seal;

namespace FILIP_1280 {

void FiLIP_1280_SEAL::encrypt_key() {
  secret_key_encrypted.clear();
  secret_key_encrypted.reserve(params.key_size_bits);
  for (size_t i = 0; i < params.key_size_bits; i++) {
    int32_t bit = (secret_key[i / 8] >> (7 - i % 8)) & 1;
    Plaintext p;
    p = bit;
    Ciphertext c;
    encryptor.encrypt(p, c);
    secret_key_encrypted.push_back(std::move(c));
  }
}

std::vector<Ciphertext> FiLIP_1280_SEAL::HE_decrypt(
    std::vector<uint8_t>& ciphertexts, size_t bits) {
  std::array<uint8_t, 16> iv = {0xab, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  FiLIP filip(params);

  std::vector<Ciphertext> out(bits);
  std::vector<Ciphertext> whitened(NB_VAR);
  std::vector<size_t> ind;
  ind.reserve(params.key_size_bits);
  for (size_t i = 0; i < params.key_size_bits; i++) ind.push_back(i);

  state_whitened whitening;

  filip.set_iv(iv);

  for (size_t i = 0; i < bits; i++) {
    filip.shuffle(ind);
    filip.set_whitening(whitening);
    for (size_t j = 0; j < NB_VAR; j++) {
      if (!whitening[j]) {
        whitened[j] = secret_key_encrypted[ind[j]];
        continue;
      }
      Plaintext p;
      p = whitening[j];
      evaluator.add_plain(secret_key_encrypted[ind[j]], p, whitened[j]);
    }
    FLIP(whitened, out[i]);
    int32_t bit = (ciphertexts[i / 8] >> (7 - i % 8)) & 1;
    if (!bit) continue;
    Plaintext p;
    p = bit;
    evaluator.add_plain_inplace(out[i], p);
  }

  return out;
}

std::vector<uint8_t> FiLIP_1280_SEAL::decrypt_result(
    std::vector<Ciphertext>& ciphertexts) {
  size_t size = ceil((double)ciphertexts.size() / 8);
  std::vector<uint8_t> res(size, 0);
  for (size_t i = 0; i < ciphertexts.size(); i++) {
    Plaintext p;
    decryptor.decrypt(ciphertexts[i], p);
    uint8_t bit = p[0];
    res[i / 8] |= (bit << (7 - i % 8));
  }
  return res;
}

void FiLIP_1280_SEAL::FLIP(std::vector<seal::Ciphertext>& state,
                           seal::Ciphertext& out) {
  size_t nb = 0;

  // Computation of Linear monomials
  out = state[nb++];
  for (size_t i = 1; i < MF[0]; i++) evaluator.add_inplace(out, state[nb++]);

  // Computation of higher degree monomials
  for (size_t i = 1; i < SIZE; i++) {
    for (size_t j = 0; j < MF[i]; j++) {
      std::vector<Ciphertext> tree;
      tree.reserve((i + 1));
      tree.push_back(state[nb++]);
      tree.push_back(state[nb++]);
      for (size_t k = 2; k < (i + 1); k++) tree.push_back(state[nb++]);
      treeMul(tree);
      evaluator.add_inplace(out, tree[0]);
    }
  }
}

void FiLIP_1280_SEAL::treeMul(std::vector<seal::Ciphertext>& tree) {
  auto len = tree.size();

  // tree mul
  while (len != 1) {
    auto new_len = len / 2;
    for (unsigned int i = 0; i < new_len; i++) {
      evaluator.multiply(tree[2 * i], tree[2 * i + 1], tree[i]);
      evaluator.relinearize_inplace(tree[i], he_rk);
    }
    if (len % 2) {
      tree[new_len] = tree[len - 1];
      new_len++;
    }
    // multree.resize(new_len);
    len = new_len;
  }
}

}  // namespace FILIP_1280
