#include "he_only_z2_tfhe.h"

namespace HE_ONLY {

void HeOnlyTFHE::encrypt_key() {
  secret_key_encrypted.init(params.key_size_bits, context);
  for (size_t i = 0; i < params.key_size_bits; i++) {
    uint8_t bit = (secret_key[i / 8] >> (7 - i % 8)) & 1;
    bootsSymEncrypt(&secret_key_encrypted[i], bit, he_sk);
  }
}

TFHECiphertextVec HeOnlyTFHE::HE_decrypt(std::vector<uint8_t>& ciphertexts,
                                         size_t bits) {
  TFHECiphertextVec out(bits, context);
  for (size_t i = 0; i < bits; i++) {
    uint8_t bit = (ciphertexts[i / 8] >> (7 - i % 8)) & 1;
    bootsSymEncrypt(&secret_key_encrypted[i], bit, he_sk);
  }

  return out;
}

std::vector<uint8_t> HeOnlyTFHE::decrypt_result(
    TFHECiphertextVec& ciphertexts) {
  size_t size = ceil((double)ciphertexts.size() / 8);
  std::vector<uint8_t> res(size, 0);
  for (size_t i = 0; i < ciphertexts.size(); i++) {
    uint8_t bit = bootsSymDecrypt(&ciphertexts[i], he_sk) & 0x1;
    res[i / 8] |= (bit << (7 - i % 8));
  }
  return res;
}

}  // namespace HE_ONLY
