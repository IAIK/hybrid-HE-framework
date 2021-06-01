#include "rasta_6_tfhe.h"

#include <iostream>

namespace RASTA_6 {

void RASTA_128_TFHE::encrypt_key() {
  secret_key_encrypted.init(params.key_size_bits, context);
  for (size_t i = 0; i < params.key_size_bits; i++) {
    uint8_t bit = (secret_key[i / 8] >> (7 - i % 8)) & 1;
    bootsSymEncrypt(&secret_key_encrypted[i], bit, he_sk);
  }
}

TFHECiphertextVec RASTA_128_TFHE::HE_decrypt(std::vector<uint8_t>& ciphertexts,
                                             size_t bits) {
  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  Rasta rasta;
  TFHECiphertextVec result(bits, context);

  for (size_t i = 0; i < num_block; i++) {
    rasta.genInstance(0, i + 1, use_m4ri);

    TFHECiphertextVec state = secret_key_encrypted;

    for (unsigned r = 1; r <= rounds; ++r) {
      std::cout << "round " << r << std::endl;
      if (use_m4ri)
        MultiplyWithGF2Matrix(rasta.m4ri_LinMatrices[r - 1], state);
      else
        MultiplyWithGF2Matrix(rasta.LinMatrices[r - 1], state);
      addConstant(state, rasta.roundconstants[r - 1]);
      sboxlayer(state);
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
      if (!bit)
        lweCopy(&result[ind], &state[k], he_pk->params->in_out_params);
      else
        bootsNOT(&result[ind], &state[k], he_pk);
    }
  }

  return result;
}

std::vector<uint8_t> RASTA_128_TFHE::decrypt_result(
    TFHECiphertextVec& ciphertexts) {
  size_t size = ceil((double)ciphertexts.size() / 8);
  std::vector<uint8_t> res(size, 0);
  for (size_t i = 0; i < ciphertexts.size(); i++) {
    uint8_t bit = bootsSymDecrypt(&ciphertexts[i], he_sk) & 0x1;
    res[i / 8] |= (bit << (7 - i % 8));
  }
  return res;
}

void RASTA_128_TFHE::MultiplyWithGF2Matrix(const std::vector<block>& matrix,
                                           TFHECiphertextVec& state) {
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

void RASTA_128_TFHE::MultiplyWithGF2Matrix(const mzd_t* matrix,
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

void RASTA_128_TFHE::addConstant(TFHECiphertextVec& state,
                                 const block& constant) {
  for (size_t i = 0; i < params.cipher_size_bits; i++) {
    if (!constant[i]) continue;
    bootsNOT(&state[i], &state[i], he_pk);
  }
}

void RASTA_128_TFHE::add(TFHECiphertextVec& state, TFHECiphertextVec& key) {
  for (size_t i = 0; i < params.cipher_size_bits; i++) {
    bootsXOR(&state[i], &state[i], &key[i], he_pk);
  }
}

void RASTA_128_TFHE::sboxlayer(TFHECiphertextVec& state) {
  TFHECiphertextVec out(params.cipher_size_bits, context);

  for (size_t i = 0; i < params.cipher_size_bits; i++) {
    int i_1 = (i + 1) % params.cipher_size_bits;
    int i_2 = (i + 2) % params.cipher_size_bits;

    bootsNOT(&out[i], &state[i_1], he_pk);
    bootsAND(&out[i], &out[i], &state[i_2], he_pk);
    bootsXOR(&out[i], &out[i], &state[i], he_pk);
  }

  state = out;
}

}  // namespace RASTA_6
