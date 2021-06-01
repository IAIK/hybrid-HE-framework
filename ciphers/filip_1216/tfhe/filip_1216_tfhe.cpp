#include "filip_1216_tfhe.h"

namespace FILIP_1216 {

void FiLIP_1216_TFHE::encrypt_key() {
  secret_key_encrypted.init(params.key_size_bits, context);
  for (size_t i = 0; i < params.key_size_bits; i++) {
    uint8_t bit = (secret_key[i / 8] >> (7 - i % 8)) & 1;
    bootsSymEncrypt(&secret_key_encrypted[i], bit, he_sk);
  }
}

TFHECiphertextVec FiLIP_1216_TFHE::HE_decrypt(std::vector<uint8_t>& ciphertexts,
                                              size_t bits) {
  std::array<uint8_t, 16> iv = {0xab, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  FiLIP filip(params);

  TFHECiphertextVec out(bits, context);
  TFHECiphertextVec whitened(NB_VAR, context);
  std::vector<size_t> ind;
  ind.reserve(params.key_size_bits);
  for (size_t i = 0; i < params.key_size_bits; i++) ind.push_back(i);

  state_whitened whitening;

  filip.set_iv(iv);

  for (size_t i = 0; i < bits; i++) {
    filip.shuffle(ind);
    filip.set_whitening(whitening);
    for (size_t j = 0; j < NB_VAR; j++) {
      if (!whitening[j])
        lweCopy(&whitened[j], &secret_key_encrypted[ind[j]],
                he_pk->params->in_out_params);
      else
        bootsNOT(&whitened[j], &secret_key_encrypted[ind[j]], he_pk);
    }
    FLIP(whitened, out[i]);
    int32_t bit = (ciphertexts[i / 8] >> (7 - i % 8)) & 1;
    if (!bit) continue;
    bootsNOT(&out[i], &out[i], he_pk);
  }

  return out;
}

std::vector<uint8_t> FiLIP_1216_TFHE::decrypt_result(
    TFHECiphertextVec& ciphertexts) {
  size_t size = ceil((double)ciphertexts.size() / 8);
  std::vector<uint8_t> res(size, 0);
  for (size_t i = 0; i < ciphertexts.size(); i++) {
    uint8_t bit = bootsSymDecrypt(&ciphertexts[i], he_sk) & 0x1;
    res[i / 8] |= (bit << (7 - i % 8));
  }
  return res;
}

void FiLIP_1216_TFHE::FLIP(TFHECiphertextVec& state, LweSample& out) {
  size_t nb = 0;

  // Computation of Linear monomials
  bootsXOR(&out, &state[nb++], &state[nb++], he_pk);
  for (size_t i = 2; i < MF[0]; i++) bootsXOR(&out, &out, &state[nb++], he_pk);

  // Computation of higher degree monomials
  for (size_t i = 1; i < SIZE; i++) {
    for (size_t j = 0; j < MF[i]; j++) {
      TFHECiphertext tmp(context);
      bootsAND(tmp, &state[nb++], &state[nb++], he_pk);
      for (size_t k = 2; k < (i + 1); k++)
        bootsAND(tmp, tmp, &state[nb++], he_pk);
      bootsXOR(&out, &out, tmp, he_pk);
    }
  }
}

}  // namespace FILIP_1216
