#include "he_only_helib.h"

using namespace helib;

namespace HE_ONLY {

void HeOnlyHElib::encrypt_key() {
  secret_key_encrypted.resize(1, Ctxt(*he_pk));
  std::vector<long> p(secret_key.begin(), secret_key.end());
  encrypt(secret_key_encrypted[0], p);
}

std::vector<Ctxt> HeOnlyHElib::HE_decrypt(std::vector<uint64_t>& ciphertexts) {
  size_t size = ciphertexts.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  std::vector<Ctxt> res(num_block, {ZeroCtxtLike, secret_key_encrypted[0]});

  for (uint64_t b = 0; b < num_block; b++) {
    std::vector<long> cipher_tmp;
    cipher_tmp.insert(
        cipher_tmp.begin(), ciphertexts.begin() + b * params.cipher_size,
        ciphertexts.begin() + std::min((b + 1) * params.cipher_size, size));
    encrypt(res[b], cipher_tmp);
  }
  return res;
}

std::vector<uint64_t> HeOnlyHElib::decrypt_result(
    std::vector<Ctxt>& ciphertext) {
  std::vector<long> res;
  decrypt(ciphertext[0], res);
  res.resize(params.plain_size);
  return std::vector<uint64_t>(res.begin(), res.end());
}

void HeOnlyHElib::add_gk_indices() {}

}  // namespace HE_ONLY
