#include "hera_5_seal.h"

using namespace seal;

namespace HERA_5 {

void HERA_SEAL::encrypt_key(bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param
  secret_key_encrypted.resize(1);
  Plaintext k;
  this->batch_encoder.encode(secret_key, k);
  encryptor.encrypt(k, secret_key_encrypted[0]);
}

std::vector<Ciphertext> HERA_SEAL::HE_decrypt(
    std::vector<uint64_t>& ciphertexts, bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param

  uint64_t nonce = 123456789;
  size_t size = ciphertexts.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  Hera hera(plain_mod);
  std::vector<Ciphertext> res(num_block);

  for (uint64_t b = 0; b < num_block; b++) {
    hera.init_shake(nonce, b);
    auto rc = hera.get_random_vector();
    Ciphertext state = first_ark(rc);

    for (uint8_t r = 1; r < HERA_R; r++) {
      std::cout << "round " << (int)r << std::endl;
      rc = hera.get_random_vector();
      matmul(state, hera.matrix);
      sbox_cube(state);
      ark(state, rc);
      print_noise(state);
    }

    std::cout << "final add" << std::endl;
    rc = hera.get_random_vector();
    matmul(state, hera.matrix);
    sbox_cube(state);
    matmul(state, hera.matrix);
    ark(state, rc);

    // add cipher
    std::vector<uint64_t> cipher_tmp;
    cipher_tmp.insert(
        cipher_tmp.begin(), ciphertexts.begin() + b * params.cipher_size,
        ciphertexts.begin() + std::min((b + 1) * params.cipher_size, size));
    Plaintext p;
    this->batch_encoder.encode(cipher_tmp, p);
    evaluator.negate_inplace(state);
    evaluator.add_plain(state, p, res[b]);
  }

  return res;
}

std::vector<uint64_t> HERA_SEAL::decrypt_result(
    std::vector<Ciphertext>& ciphertext, bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param
  Plaintext p;
  std::vector<uint64_t> res;
  decryptor.decrypt(ciphertext[0], p);
  this->batch_encoder.decode(p, res);
  res.resize(params.plain_size);
  return res;
}

void HERA_SEAL::add_gk_indices() {
  gk_indices.push_back(1);
  if (params.key_size * 2 != batch_encoder.slot_count())
    gk_indices.push_back(-((int)params.key_size));
  if (use_bsgs) {
    for (uint64_t k = 1; k < BSGS_N2; k++) gk_indices.push_back(k * BSGS_N1);
  }
}

void HERA_SEAL::sbox_cube(seal::Ciphertext& state) {
  evaluator.exponentiate_inplace(state, 3, he_rk);
}

void HERA_SEAL::matmul(seal::Ciphertext& state,
                       std::vector<std::vector<uint64_t>>& mat) {
  if (use_bsgs) {
    set_bsgs_params(BSGS_N1, BSGS_N2);
    babystep_giantstep(state, mat);
  } else {
    diagonal(state, mat);
  }
}

void HERA_SEAL::ark(seal::Ciphertext& state, std::vector<uint64_t>& rc) {
  Plaintext round_constants;
  Ciphertext tmp;
  batch_encoder.encode(rc, round_constants);
  evaluator.multiply_plain(secret_key_encrypted[0], round_constants, tmp);
  evaluator.add_inplace(state, tmp);
}

seal::Ciphertext HERA_SEAL::first_ark(std::vector<uint64_t>& rc) {
  Plaintext round_constants;
  Ciphertext result;
  std::vector<uint64_t> init = {1, 2,  3,  4,  5,  6,  7,  8,
                                9, 10, 11, 12, 13, 14, 15, 16};
  batch_encoder.encode(rc, round_constants);
  evaluator.multiply_plain(secret_key_encrypted[0], round_constants, result);
  batch_encoder.encode(init, round_constants);
  evaluator.add_plain_inplace(result, round_constants);

  return result;
}

}  // namespace HERA_5
