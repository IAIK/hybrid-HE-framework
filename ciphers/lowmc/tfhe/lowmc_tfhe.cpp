#include "lowmc_tfhe.h"

#include <iostream>

namespace LOWMC {

void LOWMC_256_128_63_14_TFHE::encrypt_key() {
  secret_key_encrypted.init(params.key_size_bits, context);
  for (size_t i = 0; i < params.key_size_bits; i++) {
    uint8_t bit = (secret_key[i / 8] >> (7 - i % 8)) & 1;
    bootsSymEncrypt(&secret_key_encrypted[i], bit, he_sk);
  }
}

TFHECiphertextVec LOWMC_256_128_63_14_TFHE::HE_decrypt(
    std::vector<uint8_t>& ciphertexts, size_t bits) {
  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  LowMC lowmc(use_m4ri);
  block iv = 0;
  TFHECiphertextVec result(bits, context);

  for (size_t i = 0; i < num_block; i++) {
    std::cout << "round 0" << std::endl;
    TFHECiphertextVec state;
    if (use_m4ri) {
      state = secret_key_encrypted;
      MultiplyWithGF2Matrix(lowmc.m4ri_KeyMatrices[0], state);
    } else
      state = MultiplyWithGF2Matrix(lowmc.KeyMatrices[0], secret_key_encrypted);
    addConstant(state, ctr(iv, i + 1));

    for (unsigned r = 1; r <= rounds; ++r) {
      std::cout << "round " << r << std::endl;
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
      if (!bit)
        lweCopy(&result[ind], &state[k], he_pk->params->in_out_params);
      else
        bootsNOT(&result[ind], &state[k], he_pk);
    }
  }
  return result;
}

std::vector<uint8_t> LOWMC_256_128_63_14_TFHE::decrypt_result(
    TFHECiphertextVec& ciphertexts) {
  size_t size = ceil((double)ciphertexts.size() / 8);
  std::vector<uint8_t> res(size, 0);
  for (size_t i = 0; i < ciphertexts.size(); i++) {
    uint8_t bit = bootsSymDecrypt(&ciphertexts[i], he_sk) & 0xFF;
    res[i / 8] |= (bit << (7 - i % 8));
  }
  return res;
}

TFHECiphertextVec LOWMC_256_128_63_14_TFHE::MultiplyWithGF2Matrix(
    const std::vector<keyblock>& matrix, const TFHECiphertextVec& key) {
  TFHECiphertextVec out(params.cipher_size_bits, context);
  for (unsigned i = 0; i < params.cipher_size_bits; ++i) {
    bool init = false;
    for (unsigned j = 0; j < params.key_size_bits; ++j) {
      if (!matrix[i][j]) continue;
      if (!init) {
        lweCopy(&out[i], &key[j], he_pk->params->in_out_params);
        init = true;
      } else
        bootsXOR(&out[i], &out[i], &key[j], he_pk);
    }
  }
  return out;
}

void LOWMC_256_128_63_14_TFHE::MultiplyWithGF2MatrixAndAdd(
    const std::vector<keyblock>& matrix, const TFHECiphertextVec& key,
    TFHECiphertextVec& state) {
  for (unsigned i = 0; i < params.cipher_size_bits; ++i) {
    for (unsigned j = 0; j < params.key_size_bits; ++j) {
      if (!matrix[i][j]) continue;
      bootsXOR(&state[i], &state[i], &key[j], he_pk);
    }
  }
}

void LOWMC_256_128_63_14_TFHE::MultiplyWithGF2Matrix(
    const std::vector<block>& matrix, TFHECiphertextVec& state) {
  TFHECiphertextVec out(params.cipher_size_bits, context);
  for (unsigned i = 0; i < params.cipher_size_bits; ++i) {
    bool init = false;
    for (unsigned j = 0; j < params.cipher_size_bits; ++j) {
      if (!matrix[i][j]) continue;
      if (!init) {
        lweCopy(&out[i], &state[j], he_pk->params->in_out_params);
        init = true;
      } else
        bootsXOR(&out[i], &out[i], &state[j], he_pk);
    }
  }
  state = out;
}

void LOWMC_256_128_63_14_TFHE::addConstant(TFHECiphertextVec& state,
                                           const block& constant) {
  for (size_t i = 0; i < params.cipher_size_bits; i++) {
    if (!constant[i]) continue;
    bootsNOT(&state[i], &state[i], he_pk);
  }
}

void LOWMC_256_128_63_14_TFHE::sboxlayer(TFHECiphertextVec& state) {
  for (unsigned i = 0; i < numofboxes; i++) {
    // invSbox(state[i * 3], state[i* 3 + 1], state[i * 3 + 2]);
    Sbox(state[i * 3], state[i * 3 + 1], state[i * 3 + 2]);
  }
}

void LOWMC_256_128_63_14_TFHE::Sbox(LweSample& a, LweSample& b, LweSample& c) {
  TFHECiphertext r_a(context);
  bootsAND(r_a, &b, &c, he_pk);
  bootsXOR(r_a, r_a, &a, he_pk);
  bootsXOR(r_a, r_a, &b, he_pk);
  bootsXOR(r_a, r_a, &c, he_pk);

  TFHECiphertext r_b(context);
  bootsAND(r_b, &a, &c, he_pk);
  bootsXOR(r_b, r_b, &b, he_pk);
  bootsXOR(r_b, r_b, &c, he_pk);

  TFHECiphertext r_c(context);
  bootsAND(r_c, &a, &b, he_pk);
  bootsXOR(r_c, r_c, &c, he_pk);

  lweCopy(&a, r_a, he_pk->params->in_out_params);
  lweCopy(&b, r_b, he_pk->params->in_out_params);
  lweCopy(&c, r_c, he_pk->params->in_out_params);
}

void LOWMC_256_128_63_14_TFHE::invSbox(LweSample& a, LweSample& b,
                                       LweSample& c) {
  TFHECiphertext r_a(context);
  bootsAND(r_a, &b, &c, he_pk);
  bootsXOR(r_a, r_a, &b, he_pk);
  bootsXOR(r_a, r_a, &c, he_pk);
  bootsXOR(r_a, r_a, &a, he_pk);

  TFHECiphertext r_b(context);
  bootsAND(r_b, &a, &c, he_pk);
  bootsXOR(r_b, r_b, &b, he_pk);

  TFHECiphertext r_c(context);
  bootsAND(r_c, &a, &b, he_pk);
  bootsXOR(r_c, r_c, &b, he_pk);
  bootsXOR(r_c, r_c, &c, he_pk);

  lweCopy(&a, r_a, he_pk->params->in_out_params);
  lweCopy(&b, r_b, he_pk->params->in_out_params);
  lweCopy(&c, r_c, he_pk->params->in_out_params);
}

void LOWMC_256_128_63_14_TFHE::MultiplyWithGF2MatrixAndAdd(
    const mzd_t* matrix, const TFHECiphertextVec& key,
    TFHECiphertextVec& state) {
  rci_t k = floor(log2(matrix->ncols)) - 2;
  if (k < 1) k = 1;

  std::vector<rci_t> L(1 << k);
  TFHECiphertextVec T(1 << k, context);

  L[0] = 0;
  for (rci_t i = 0; i < matrix->ncols; i += k) {
    if (i + k > matrix->ncols) k = matrix->ncols - i;
    for (rci_t j = 1; j < 1 << k; j++) {
      rci_t rowneeded = i + m4ri_codebook[k]->inc[j - 1];
      L[m4ri_codebook[k]->ord[j]] = j;
      if (j == 1)
        lweCopy(&T[j], &key[rowneeded], he_pk->params->in_out_params);
      else
        bootsXOR(&T[j], &T[j - 1], &key[rowneeded], he_pk);
    }

    for (rci_t j = 0; j < matrix->nrows; j++) {
      rci_t x = L[mzd_read_bits_int(matrix, j, i, k)];
      if (!x) continue;

      bootsXOR(&state[j], &state[j], &T[x], he_pk);
    }
  }
}

void LOWMC_256_128_63_14_TFHE::MultiplyWithGF2Matrix(const mzd_t* matrix,
                                                     TFHECiphertextVec& state) {
  TFHECiphertextVec out(params.cipher_size_bits, context);

  rci_t k = floor(log2(matrix->ncols)) - 2;
  if (k < 1) k = 1;

  block init = 0;
  std::vector<rci_t> L(1 << k);
  TFHECiphertextVec T(1 << k, context);

  L[0] = 0;
  for (rci_t i = 0; i < matrix->ncols; i += k) {
    if (i + k > matrix->ncols) k = matrix->ncols - i;
    for (rci_t j = 1; j < 1 << k; j++) {
      rci_t rowneeded = i + m4ri_codebook[k]->inc[j - 1];
      L[m4ri_codebook[k]->ord[j]] = j;
      if (j == 1)
        lweCopy(&T[j], &state[rowneeded], he_pk->params->in_out_params);
      else
        bootsXOR(&T[j], &T[j - 1], &state[rowneeded], he_pk);
    }

    for (rci_t j = 0; j < matrix->nrows; j++) {
      rci_t x = L[mzd_read_bits_int(matrix, j, i, k)];
      if (!x) continue;

      if (init[j] == 0) {
        lweCopy(&out[j], &T[x], he_pk->params->in_out_params);
        init[j] = 1;
      } else
        bootsXOR(&out[j], &out[j], &T[x], he_pk);
    }
  }
  state = out;
}

}  // namespace LOWMC
