#include "rasta_6_seal.h"

using namespace seal;

namespace RASTA_6 {

void RASTA_128_SEAL::encrypt_key() {
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

std::vector<Ciphertext> RASTA_128_SEAL::HE_decrypt(
    std::vector<uint8_t>& ciphertexts, size_t bits) {
  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  Rasta rasta;
  std::vector<seal::Ciphertext> result(bits);

  for (size_t i = 0; i < num_block; i++) {
    rasta.genInstance(0, i + 1, use_m4ri);

    std::vector<seal::Ciphertext> state = secret_key_encrypted;

    for (unsigned r = 1; r <= rounds; ++r) {
      std::cout << "round " << r << std::endl;
      if (use_m4ri)
        MultiplyWithGF2Matrix(rasta.m4ri_LinMatrices[r - 1], state);
      else
        MultiplyWithGF2Matrix(rasta.LinMatrices[r - 1], state);
      addConstant(state, rasta.roundconstants[r - 1]);
      sboxlayer(state);
      print_noise(state);
    }

    std::cout << "final add" << std::endl;
    if (use_m4ri)
      MultiplyWithGF2Matrix(rasta.m4ri_LinMatrices[rounds], state);
    else
      MultiplyWithGF2Matrix(rasta.LinMatrices[rounds], state);
    addConstant(state, rasta.roundconstants[rounds]);
    add(state, secret_key_encrypted);

    // add cipher
    for (size_t k = 0; k < blocksize && i * blocksize + k < bits; k++) {
      size_t ind = i * blocksize + k;
      int32_t bit = (ciphertexts[ind / 8] >> (7 - ind % 8)) & 1;
      if (!bit) {
        result[ind] = state[k];
        continue;
      }
      Plaintext p;
      p = bit;
      evaluator.add_plain(state[k], p, result[ind]);
    }
  }

  return result;
}

std::vector<uint8_t> RASTA_128_SEAL::decrypt_result(
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

void RASTA_128_SEAL::MultiplyWithGF2Matrix(const std::vector<block>& matrix,
                                           std::vector<Ciphertext>& state) {
  std::vector<Ciphertext> out;
  out.reserve(params.cipher_size_bits);
  for (unsigned i = 0; i < params.cipher_size_bits; ++i) {
    bool init = false;
    for (unsigned j = 0; j < params.cipher_size_bits; ++j) {
      if (!matrix[i][j]) continue;
      if (!init) {
        out.push_back(state[j]);
        init = true;
      } else
        evaluator.add_inplace(out[i], state[j]);
    }
  }
  state = out;
}

void RASTA_128_SEAL::MultiplyWithGF2Matrix(const mzd_t* matrix,
                                           std::vector<Ciphertext>& state) {
  std::vector<Ciphertext> out(matrix->nrows);

  rci_t k = floor(log2(matrix->ncols)) - 2;
  if (k < 1) k = 1;

  block init = 0;
  std::vector<rci_t> L(1 << k);
  std::vector<Ciphertext> T(1 << k);

  L[0] = 0;
  for (rci_t i = 0; i < matrix->ncols; i += k) {
    if (i + k > matrix->ncols) k = matrix->ncols - i;
    for (rci_t j = 1; j < 1 << k; j++) {
      rci_t rowneeded = i + m4ri_codebook[k]->inc[j - 1];
      L[m4ri_codebook[k]->ord[j]] = j;
      T[j] = state[rowneeded];
      if (j > 1) evaluator.add_inplace(T[j], T[j - 1]);
    }

    for (rci_t j = 0; j < matrix->nrows; j++) {
      rci_t x = L[mzd_read_bits_int(matrix, j, i, k)];
      if (!x) continue;

      if (init[j] == 0) {
        out[j] = T[x];
        init[j] = 1;
      } else
        evaluator.add_inplace(out[j], T[x]);
    }
  }
  state = out;
}

void RASTA_128_SEAL::addConstant(std::vector<Ciphertext>& state,
                                 const block& constant) {
  for (size_t i = 0; i < params.cipher_size_bits; i++) {
    if (!constant[i]) continue;
    Plaintext p;
    p = constant[i];
    evaluator.add_plain_inplace(state[i], p);
  }
}

void RASTA_128_SEAL::add(std::vector<Ciphertext>& state,
                         const std::vector<Ciphertext>& key) {
  for (size_t i = 0; i < params.cipher_size_bits; i++) {
    evaluator.add_inplace(state[i], key[i]);
  }
}

void RASTA_128_SEAL::sboxlayer(std::vector<Ciphertext>& state) {
  std::vector<Ciphertext> out;
  out.reserve(state.size());
  Plaintext p;
  p = 1;

  for (size_t i = 0; i < params.cipher_size_bits; i++) {
    int i_1 = (i + 1) % params.cipher_size_bits;
    int i_2 = (i + 2) % params.cipher_size_bits;

    Ciphertext tmp;
    evaluator.add_plain(state[i_1], p, tmp);
    evaluator.multiply_inplace(tmp, state[i_2]);
    evaluator.relinearize_inplace(tmp, he_rk);
    evaluator.add_inplace(tmp, state[i]);
    out.push_back(std::move(tmp));
  }

  state = out;
}

}  // namespace RASTA_6
