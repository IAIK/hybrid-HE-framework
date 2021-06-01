#include "he_only_seal.h"

using namespace seal;

namespace HE_ONLY {

void HeOnlySEAL::encrypt_key(bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param
  secret_key_encrypted.resize(1);
  Plaintext k;
  this->batch_encoder.encode(secret_key, k);
  encryptor.encrypt(k, secret_key_encrypted[0]);
}

//----------------------------------------------------------------

std::vector<Ciphertext> HeOnlySEAL::HE_decrypt(
    std::vector<uint64_t>& ciphertexts, bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param
  size_t size = ciphertexts.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  std::vector<Ciphertext> res(num_block);

  Plaintext p;
  for (uint64_t b = 0; b < num_block; b++) {
    std::vector<uint64_t> cipher_tmp;
    cipher_tmp.insert(
        cipher_tmp.begin(), ciphertexts.begin() + b * params.cipher_size,
        ciphertexts.begin() + std::min((b + 1) * params.cipher_size, size));
    this->batch_encoder.encode(cipher_tmp, p);
    encryptor.encrypt(p, res[b]);
  }
  return res;
}

//----------------------------------------------------------------

std::vector<uint64_t> HeOnlySEAL::decrypt_result(
    std::vector<Ciphertext>& ciphertext, bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param
  Plaintext p;
  std::vector<uint64_t> res;
  decryptor.decrypt(ciphertext[0], p);
  this->batch_encoder.decode(p, res);
  res.resize(params.plain_size);
  return res;
}

//----------------------------------------------------------------

void HeOnlySEAL::add_gk_indices() {}

}  // namespace HE_ONLY
