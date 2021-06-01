#include "masta_5_seal.h"

using namespace seal;

namespace MASTA_5 {

void MASTA_128_SEAL::encrypt_key(bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param
  secret_key_encrypted.resize(1);
  Plaintext k;
  this->batch_encoder.encode(secret_key, k);
  encryptor.encrypt(k, secret_key_encrypted[0]);
}

std::vector<Ciphertext> MASTA_128_SEAL::HE_decrypt(
    std::vector<uint64_t>& ciphertexts, bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param

  uint64_t nonce = 123456789;
  size_t size = ciphertexts.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  Masta masta(plain_mod);
  std::vector<Ciphertext> res(num_block);

  for (uint64_t b = 0; b < num_block; b++) {
    masta.init_shake(nonce, b);
    Ciphertext state = secret_key_encrypted[0];

    for (uint8_t r = 1; r <= MASTA_R; r++) {
      std::cout << "round " << (int)r << std::endl;
      auto mat = masta.get_random_matrix();
      auto rc = masta.get_random_vector();
      matmul(state, mat);
      add_rc(state, rc);
      sbox(state);
      print_noise(state);
    }

    std::cout << "final add" << std::endl;
    auto mat = masta.get_random_matrix();
    auto rc = masta.get_random_vector();
    matmul(state, mat);
    add_rc(state, rc);
    evaluator.add_inplace(state, secret_key_encrypted[0]);

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

std::vector<uint64_t> MASTA_128_SEAL::decrypt_result(
    std::vector<Ciphertext>& ciphertext, bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param
  Plaintext p;
  std::vector<uint64_t> res;
  decryptor.decrypt(ciphertext[0], p);
  this->batch_encoder.decode(p, res);
  res.resize(params.plain_size);
  return res;
}

void MASTA_128_SEAL::add_gk_indices() {
  gk_indices.push_back(1);
  if (params.key_size * 2 != batch_encoder.slot_count())
    gk_indices.push_back(-((int)params.key_size));
  if (use_bsgs) {
    for (uint64_t k = 1; k < BSGS_N2; k++) gk_indices.push_back(k * BSGS_N1);
  }
}

void MASTA_128_SEAL::add_rc(seal::Ciphertext& state,
                            std::vector<uint64_t>& rc) {
  Plaintext round_constants;
  batch_encoder.encode(rc, round_constants);
  evaluator.add_plain_inplace(state, round_constants);
}

void MASTA_128_SEAL::sbox(seal::Ciphertext& state) {
  std::vector<uint64_t> tmp(params.key_size, 1);
  Plaintext p;
  batch_encoder.encode(tmp, p);

  // non-full-packed rotation preparation
  if (batch_encoder.slot_count() != params.key_size * 2) {
    Ciphertext state_rot;
    evaluator.rotate_rows(state, -((int)params.key_size), he_gk, state_rot);
    evaluator.add_inplace(state, state_rot);
  }

  Ciphertext state_rot1, state_rot2;
  evaluator.rotate_rows(state, 1, he_gk, state_rot1);
  evaluator.rotate_rows(state_rot1, 1, he_gk, state_rot2);

  evaluator.add_plain_inplace(state_rot1, p);
  evaluator.multiply_inplace(state_rot1, state_rot2);
  evaluator.relinearize_inplace(state_rot1, he_rk);
  evaluator.add_inplace(state, state_rot1);

  if (batch_encoder.slot_count() != params.key_size * 2) {
    evaluator.multiply_plain_inplace(state, p);
  }
}

void MASTA_128_SEAL::matmul(seal::Ciphertext& state,
                            std::vector<std::vector<uint64_t>>& mat) {
  if (use_bsgs) {
    set_bsgs_params(BSGS_N1, BSGS_N2);
    babystep_giantstep(state, mat);
  } else {
    diagonal(state, mat);
  }
}

}  // namespace MASTA_5
