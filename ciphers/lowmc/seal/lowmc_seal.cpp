#include "lowmc_seal.h"

using namespace seal;

namespace LOWMC {

void LOWMC_256_128_63_14_SEAL::encrypt_key() {
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

std::vector<Ciphertext> LOWMC_256_128_63_14_SEAL::HE_decrypt(
    std::vector<uint8_t>& ciphertexts, size_t bits) {
  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  LowMC lowmc(use_m4ri);
  block iv = 0;
  std::vector<seal::Ciphertext> result(bits);

  for (size_t i = 0; i < num_block; i++) {
    std::cout << "round 0" << std::endl;
    std::vector<Ciphertext> state;
    if (use_m4ri) {
      state = secret_key_encrypted;
      MultiplyWithGF2Matrix(lowmc.m4ri_KeyMatrices[0], state);
    } else
      state = MultiplyWithGF2Matrix(lowmc.KeyMatrices[0], secret_key_encrypted);
    addConstant(state, ctr(iv, i + 1));

    for (unsigned r = 1; r <= rounds; ++r) {
      std::cout << "round " << r << std::endl;
      print_noise(state);
      sboxlayer(state);
      if (use_m4ri) {
        MultiplyWithGF2Matrix(lowmc.m4ri_LinMatrices[r - 1], state);
        MultiplyWithGF2MatrixAndAdd(lowmc.m4ri_KeyMatrices[r],
                                    secret_key_encrypted, state);
      } else {
        MultiplyWithGF2Matrix(lowmc.LinMatrices[r - 1], state);
        MultiplyWithGF2MatrixAndAdd(lowmc.KeyMatrices[r], secret_key_encrypted,
                                    state);
      }
      addConstant(state, lowmc.roundconstants[r - 1]);
    }

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

std::vector<uint8_t> LOWMC_256_128_63_14_SEAL::decrypt_result(
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

std::vector<seal::Ciphertext> LOWMC_256_128_63_14_SEAL::MultiplyWithGF2Matrix(
    const std::vector<keyblock>& matrix, const std::vector<Ciphertext>& key) {
  std::vector<Ciphertext> out;
  out.reserve(params.cipher_size_bits);
  for (unsigned i = 0; i < params.cipher_size_bits; ++i) {
    bool init = false;
    for (unsigned j = 0; j < params.key_size_bits; ++j) {
      if (!matrix[i][j]) continue;
      if (!init) {
        out.push_back(key[j]);
        init = true;
      } else
        evaluator.add_inplace(out[i], key[j]);
    }
  }
  return out;
}

void LOWMC_256_128_63_14_SEAL::MultiplyWithGF2MatrixAndAdd(
    const std::vector<keyblock>& matrix, const std::vector<Ciphertext>& key,
    std::vector<Ciphertext>& state) {
  for (unsigned i = 0; i < params.cipher_size_bits; ++i) {
    for (unsigned j = 0; j < params.key_size_bits; ++j) {
      if (!matrix[i][j]) continue;
      evaluator.add_inplace(state[i], key[j]);
    }
  }
}

void LOWMC_256_128_63_14_SEAL::MultiplyWithGF2Matrix(
    const std::vector<block>& matrix, std::vector<Ciphertext>& state) {
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

void LOWMC_256_128_63_14_SEAL::addConstant(std::vector<Ciphertext>& state,
                                           const block& constant) {
  for (size_t i = 0; i < params.cipher_size_bits; i++) {
    if (!constant[i]) continue;
    Plaintext p;
    p = constant[i];
    evaluator.add_plain_inplace(state[i], p);
  }
}

void LOWMC_256_128_63_14_SEAL::sboxlayer(std::vector<seal::Ciphertext>& state) {
  for (unsigned i = 0; i < numofboxes; i++) {
    // invSbox(state[i * 3], state[i* 3 + 1], state[i * 3 + 2]);
    Sbox(state[i * 3], state[i * 3 + 1], state[i * 3 + 2]);
  }
}

void LOWMC_256_128_63_14_SEAL::Sbox(seal::Ciphertext& a, seal::Ciphertext& b,
                                    seal::Ciphertext& c) {
  seal::Ciphertext r_a, r_b, r_c;
  evaluator.multiply(b, c, r_a);
  evaluator.relinearize_inplace(r_a, he_rk);
  evaluator.add_inplace(r_a, a);
  evaluator.add_inplace(r_a, b);
  evaluator.add_inplace(r_a, c);

  evaluator.multiply(a, c, r_b);
  evaluator.relinearize_inplace(r_b, he_rk);
  evaluator.add_inplace(r_b, b);
  evaluator.add_inplace(r_b, c);

  evaluator.multiply(a, b, r_c);
  evaluator.relinearize_inplace(r_c, he_rk);
  evaluator.add_inplace(r_c, c);

  a = r_a;
  b = r_b;
  c = r_c;
}

void LOWMC_256_128_63_14_SEAL::invSbox(seal::Ciphertext& a, seal::Ciphertext& b,
                                       seal::Ciphertext& c) {
  seal::Ciphertext r_a, r_b, r_c;
  evaluator.multiply(b, c, r_a);
  evaluator.relinearize_inplace(r_a, he_rk);
  evaluator.add_inplace(r_a, b);
  evaluator.add_inplace(r_a, c);
  evaluator.add_inplace(r_a, a);

  evaluator.multiply(a, c, r_b);
  evaluator.relinearize_inplace(r_b, he_rk);
  evaluator.add_inplace(r_b, b);

  evaluator.multiply(a, b, r_c);
  evaluator.relinearize_inplace(r_c, he_rk);
  evaluator.add_inplace(r_c, b);
  evaluator.add_inplace(r_c, c);

  a = r_a;
  b = r_b;
  c = r_c;
}

void LOWMC_256_128_63_14_SEAL::MultiplyWithGF2MatrixAndAdd(
    const mzd_t* matrix, const std::vector<Ciphertext>& key,
    std::vector<Ciphertext>& state) {
  rci_t k = floor(log2(matrix->ncols)) - 2;
  if (k < 1) k = 1;

  std::vector<rci_t> L(1 << k);
  std::vector<Ciphertext> T(1 << k);

  L[0] = 0;
  for (rci_t i = 0; i < matrix->ncols; i += k) {
    if (i + k > matrix->ncols) k = matrix->ncols - i;
    for (rci_t j = 1; j < 1 << k; j++) {
      rci_t rowneeded = i + m4ri_codebook[k]->inc[j - 1];
      L[m4ri_codebook[k]->ord[j]] = j;
      T[j] = key[rowneeded];
      if (j > 1) evaluator.add_inplace(T[j], T[j - 1]);
    }

    for (rci_t j = 0; j < matrix->nrows; j++) {
      rci_t x = L[mzd_read_bits_int(matrix, j, i, k)];
      if (!x) continue;

      evaluator.add_inplace(state[j], T[x]);
    }
  }
}

void LOWMC_256_128_63_14_SEAL::MultiplyWithGF2Matrix(
    const mzd_t* matrix, std::vector<Ciphertext>& state) {
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

}  // namespace LOWMC
